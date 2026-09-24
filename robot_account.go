package harbor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	harborRobotAccountType = "robot_account"
	robotWALKind           = "robot_account"
)

// robotWALEntry records a robot account being created, so it can be deleted if the request fails.
type robotWALEntry struct {
	Name    string `json:"name"`
	Nonce   string `json:"nonce"`
	URL     string `json:"harbor_url"`
	Level   string `json:"level"`
	Project string `json:"project,omitempty"`
}

// harborToken defines a secret to store for a given role
// and how it should be revoked or renewed.
func (b *harborBackend) harborToken() *framework.Secret {
	return &framework.Secret{
		Type: harborRobotAccountType,
		Fields: map[string]*framework.FieldSchema{
			"robot_account": {
				Type:        framework.TypeString,
				Description: "Harbor Robot account",
			},
		},
		Revoke: b.robotAccountRevoke,
		Renew:  b.robotAccountRenew,
	}
}

// robotAccountRevoke deletes the robot account recorded on the lease, by ID, from the Harbor that issued it
func (b *harborBackend) robotAccountRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	id, err := leaseInt64(req.Secret.InternalData, "robot_account_id")
	if err != nil {
		return nil, b.corruptLease(err, "robot_account_id")
	}
	name, err := leaseString(req.Secret.InternalData, "robot_account_name")
	if err != nil {
		return nil, b.corruptLease(err, "robot_account_name")
	}
	harborURL, err := leaseString(req.Secret.InternalData, "harbor_url")
	if err != nil {
		return nil, b.corruptLease(err, "harbor_url")
	}
	robotName, err := leaseString(req.Secret.InternalData, "robot_name")
	if err != nil {
		robotName = unprefixedRobotName(name)
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if client.url != harborURL {
		return nil, fmt.Errorf("robot account was issued by Harbor %q but the backend is configured for %q, refusing to revoke", harborURL, client.url)
	}

	robot, err := client.GetRobotAccountByID(ctx, id)
	if isNotFound(err) {
		b.Logger().Info("robot account is already gone from Harbor, nothing to revoke", "id", id, "name", name)
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error reading robot account %d: %w", id, err)
	}

	if !sameRobotAccount(robot.Name, robotName, configRobotPrefix(config), "") {
		return nil, fmt.Errorf("robot account %d is named %q instead of %q, refusing to delete", id, robot.Name, robotName)
	}

	if err := client.DeleteRobotAccountByID(ctx, id); err != nil && !isNotFound(err) {
		return nil, fmt.Errorf("error revoking robot account %d: %w", id, err)
	}

	b.Logger().Info("revoked a Harbor robot account", "id", id, "name", robot.Name)

	return nil, nil
}

// corruptLease reports a lease Vault cannot revoke from: the robot account stays live in Harbor
// until an operator deletes it, and the missing field is the only lead.
func (b *harborBackend) corruptLease(err error, key string) error {
	b.Logger().Warn("cannot revoke a robot account from this lease", "key", key, "error", err)
	return err
}

// robotAccountRenew extends the lease, never beyond the expiry of the Harbor robot account
func (b *harborBackend) robotAccountRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	role, err := leaseString(req.Secret.InternalData, "role")
	if err != nil {
		return nil, err
	}

	leaseMaxTTL, err := leaseInt64(req.Secret.InternalData, "max_ttl")
	if err != nil {
		return nil, err
	}

	roleEntry, err := b.getRole(ctx, req.Storage, role)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	resp := &logical.Response{Secret: req.Secret}
	maxTTL := time.Duration(leaseMaxTTL) * time.Second

	if roleEntry != nil {
		if roleEntry.MaxTTL > 0 && roleEntry.MaxTTL < maxTTL {
			maxTTL = roleEntry.MaxTTL
		}
		if roleEntry.TTL > 0 {
			resp.Secret.TTL = roleEntry.TTL
		}
	}
	resp.Secret.MaxTTL = maxTTL

	return resp, nil
}

// walRollback undoes Harbor changes whose request did not complete.
func (b *harborBackend) walRollback(ctx context.Context, req *logical.Request, kind string, data interface{}) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}

	switch kind {
	case robotWALKind, rootRobotWALKind:
		var entry robotWALEntry
		if err := json.Unmarshal(raw, &entry); err != nil {
			return fmt.Errorf("error decoding WAL entry: %w", err)
		}
		if entry.Name == "" || entry.Nonce == "" {
			return nil
		}
		if kind == rootRobotWALKind {
			return b.rootRobotWALRollback(ctx, req.Storage, &entry)
		}
		config, err := getConfig(ctx, req.Storage)
		if err != nil {
			return err
		}
		return b.deleteWALRobot(ctx, req.Storage, &entry, config)
	case rootUserWALKind:
		var entry rootUserWALEntry
		if err := json.Unmarshal(raw, &entry); err != nil {
			return fmt.Errorf("error decoding WAL entry: %w", err)
		}
		if entry.Username == "" || entry.Password == "" {
			return nil
		}
		return b.rootUserWALRollback(ctx, req.Storage, &entry)
	default:
		return fmt.Errorf("unknown WAL entry kind %q", kind)
	}
}

// deleteWALRobot deletes the robot account created by the request that wrote the WAL entry, if any.
// The robot account of the principal config describes is never deleted: rolling back a rotation
// that was already stored would lock the backend out of Harbor.
func (b *harborBackend) deleteWALRobot(ctx context.Context, s logical.Storage, entry *robotWALEntry, config *harborConfig) error {
	client, err := b.getClient(ctx, s)
	if errors.Is(err, errBackendNotConfigured) {
		b.Logger().Warn("backend is not configured, dropping robot account WAL entry", "name", entry.Name, "harbor_url", entry.URL)
		return nil
	}
	if err != nil {
		return err
	}

	if client.url != entry.URL {
		b.Logger().Warn("configured Harbor differs from WAL entry, dropping robot account WAL entry", "name", entry.Name, "harbor_url", entry.URL)
		return nil
	}

	// A fuzzy filter: an exact name= value is unescaped twice by Harbor, turning a project robot's "+" into a space.
	query := "Level=system,name=~" + entry.Name
	if entry.Level == robotKindProject {
		projectID, err := client.GetProjectID(ctx, entry.Project)
		if isNotFound(err) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("error resolving project %q: %w", entry.Project, err)
		}
		query = fmt.Sprintf("Level=project,ProjectID=%d,name=~%s", projectID, entry.Name)
	}

	robots, err := client.ListRobotAccounts(ctx, query)
	if err != nil {
		return fmt.Errorf("error listing robot accounts: %w", err)
	}

	description := robotDescription(entry.Nonce)
	for _, robot := range robots {
		if robot == nil || robot.Description != description || !sameRobotAccount(robot.Name, entry.Name, configRobotPrefix(config), entry.Project) {
			continue
		}
		if isPrincipalRobot(config, robot) {
			b.Logger().Warn("WAL entry matches the configured principal, dropping it", "id", robot.ID, "name", entry.Name)
			continue
		}
		if err := client.DeleteRobotAccountByID(ctx, robot.ID); err != nil && !isNotFound(err) {
			return fmt.Errorf("error deleting robot account %d: %w", robot.ID, err)
		}
	}

	return nil
}

// unprefixedRobotName strips Harbor's default "robot$" prefix and a project robot's "<project>+"
// from a robot name; names generated by Vault contain neither separator.
func unprefixedRobotName(harborName string) string {
	return harborName[strings.LastIndexAny(harborName, "$+")+1:]
}

// sameRobotAccount reports whether the robot account Harbor names harborName is the one Vault named
// name, in project when it is a project robot. Matching what surrounds the name instead, as a
// suffix does, is both too weak (any name ending in it passes) and fail-open (an account renamed
// around it passes too): what Harbor prepends is compared exactly, be it the "<project>+" and the
// robot_name_prefix it separates with "$" or "+", or prefix, the robot_name_prefix the backend
// recorded, which is the only way to tell one carrying neither separator from the name itself.
func sameRobotAccount(harborName, name, prefix, project string) bool {
	if name == "" {
		return false
	}
	if unprefixedRobotName(harborName) == name {
		return true
	}
	if prefix == "" {
		return false
	}
	return harborName == prefix+name || (project != "" && harborName == prefix+project+"+"+name)
}

// configRobotPrefix returns the robot_name_prefix the backend recorded, if any.
func configRobotPrefix(config *harborConfig) string {
	if config == nil {
		return ""
	}
	return config.RobotPrefix
}

func leaseString(data map[string]interface{}, key string) (string, error) {
	raw, ok := data[key]
	if !ok {
		return "", fmt.Errorf("lease is missing %s internal data", key)
	}
	v, ok := raw.(string)
	if !ok || v == "" {
		return "", fmt.Errorf("lease has invalid %s internal data", key)
	}
	return v, nil
}

// leaseInt64 accepts the numeric types InternalData holds in memory and after a JSON round-trip.
func leaseInt64(data map[string]interface{}, key string) (int64, error) {
	raw, ok := data[key]
	if !ok {
		return 0, fmt.Errorf("lease is missing %s internal data", key)
	}

	var v int64
	var err error
	switch n := raw.(type) {
	case int64:
		v = n
	case int:
		v = int64(n)
	case float64:
		if n != math.Trunc(n) || n > math.MaxInt64 || n < math.MinInt64 {
			err = errors.New("not an integer")
		}
		v = int64(n)
	case json.Number:
		v, err = n.Int64()
	case string:
		v, err = strconv.ParseInt(n, 10, 64)
	default:
		err = errors.New("unexpected type")
	}
	if err != nil || v <= 0 {
		return 0, fmt.Errorf("lease has invalid %s internal data", key)
	}
	return v, nil
}
