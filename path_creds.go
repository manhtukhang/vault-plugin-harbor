package harbor

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	harborModel "github.com/mittwald/goharbor-client/v5/apiv2/model"
)

const (
	// #nosec G101 -- help text, not a credential
	pathCredsHelpSyn  = `Generate a Harbor robot account from a specific Vault role.`
	pathCredsHelpDesc = `This path generates a Harbor robot account
based on a particular role.`

	day = 24 * time.Hour
	// robotExpiryMargin keeps the Harbor robot alive past the lease despite clock skew and latency.
	robotExpiryMargin = time.Hour

	robotNameSeparators    = "._-"
	robotNameDisplayMaxLen = 32
	robotNameMaxLen        = 128
	robotNameTimestampLen  = 19
)

var (
	robotNameInvalidChars   = regexp.MustCompile(`[^a-z0-9._-]+`)
	robotNameSeparatorsRuns = regexp.MustCompile(`[._-]{2,}`)
)

// harborRobotAccount defines a secret for the Harbor robot account
type harborRobotAccount struct {
	ID        int64  `json:"robot_account_id"`
	Name      string `json:"robot_account_name"`
	Secret    string `json:"robot_account_secret"`
	AuthToken string `json:"robot_account_auth_token"`
}

// pathCreds extends the Vault API with a `/creds`
// endpoint for a role.
func pathCreds(b *harborBackend) *framework.Path {
	return &framework.Path{
		Pattern: "creds/(?P<name>" + nameRegex + ")",
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the role",
				Required:    true,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback:                    b.pathCredsRead,
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
		},
		HelpSynopsis:    pathCredsHelpSyn,
		HelpDescription: pathCredsHelpDesc,
	}
}

// pathCredsRead creates a new Harbor robot account each time it is called if a
// role exists.
func (b *harborBackend) pathCredsRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleName := d.Get("name").(string)

	roleEntry, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if roleEntry == nil {
		return logical.ErrorResponse("unknown role: %s", roleName), nil
	}

	return b.createCreds(ctx, req, roleName, roleEntry)
}

// createCreds creates a new Harbor robot account to store into the Vault backend, generates
// a response with the robot account information, and checks the TTL and MaxTTL attributes.
func (b *harborBackend) createCreds(
	ctx context.Context,
	req *logical.Request,
	roleName string,
	role *harborRoleEntry,
) (*logical.Response, error) {
	if err := validatePermissions(role.Permissions, role.AllowAllProjects); err != nil {
		return logical.ErrorResponse("role %q has permissions that are not allowed: %s", roleName, err), nil
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	maxTTL := b.effectiveMaxTTL(role)
	wal := &robotWALEntry{URL: client.url, Level: robotLevel(role.Permissions)}

	maxNameLen := robotNameMaxLen
	if wal.Level == robotKindProject {
		wal.Project = role.Permissions[0].Namespace
		// Harbor stores project robots as "<project>+<name>" in varchar(255).
		maxNameLen = min(maxNameLen, harborNameMaxLen-1-len(wal.Project))
	}
	if maxNameLen <= robotNameTimestampLen+1 {
		return logical.ErrorResponse("project name %q is too long for a Harbor robot account name", wal.Project), nil
	}

	wal.Name = robotAccountName(roleName, req.DisplayName, maxNameLen, time.Now())
	if wal.Nonce, err = newNonce(); err != nil {
		return nil, err
	}

	robotAccount, err := b.createRobotAccount(ctx, req.Storage, client, wal, maxTTL, configRobotPrefix(config), withImplicitPull(role.Permissions))
	if err != nil {
		return nil, err
	}

	b.Logger().Info("issued a Harbor robot account",
		"role", roleName,
		"id", robotAccount.ID,
		"name", robotAccount.Name,
		"level", wal.Level,
		"project", wal.Project,
		"harbor_url", client.url,
		"max_ttl", maxTTL.String(),
	)

	// The response is divided into two objects (1) internal data and (2) data.
	resp := b.Secret(harborRobotAccountType).Response(map[string]interface{}{
		"robot_account_id":         robotAccount.ID,
		"robot_account_name":       robotAccount.Name,
		"robot_account_secret":     robotAccount.Secret,
		"robot_account_auth_token": robotAccount.AuthToken,
	}, map[string]interface{}{
		"role":               roleName,
		"robot_account_id":   robotAccount.ID,
		"robot_account_name": robotAccount.Name,
		"robot_name":         wal.Name,
		"harbor_url":         client.url,
		"max_ttl":            int64(maxTTL / time.Second),
	})

	if role.TTL > 0 {
		resp.Secret.TTL = role.TTL
	}

	resp.Secret.MaxTTL = maxTTL

	return resp, nil
}

// createRobotAccount uses the Harbor client to create and return a robot account.
// A WAL entry covers the window where Harbor created the robot but the request failed.
func (b *harborBackend) createRobotAccount(
	ctx context.Context,
	s logical.Storage,
	client *harborClient,
	wal *robotWALEntry,
	maxTTL time.Duration,
	prefix string,
	permissions []*harborModel.RobotPermission,
) (*harborRobotAccount, error) {
	walID, err := framework.PutWAL(ctx, s, robotWALKind, wal)
	if err != nil {
		return nil, fmt.Errorf("error writing WAL entry: %w", err)
	}

	robotCreated, err := client.NewRobotAccount(ctx, &harborModel.RobotCreate{
		Name:        wal.Name,
		Description: robotDescription(wal.Nonce),
		Disable:     false,
		Duration:    harborDurationDays(maxTTL),
		Level:       wal.Level,
		Permissions: permissions,
	})
	if err != nil {
		// An intermediary can answer 4xx for a request Harbor committed, so the WAL entry is kept
		// whatever the outcome; rollback is exact and idempotent through the description nonce.
		return nil, fmt.Errorf("error creating Harbor robot account: %w", err)
	}

	if robotCreated == nil || robotCreated.ID <= 0 {
		return nil, errors.New("error creating Harbor robot account: invalid response from Harbor")
	}

	if robotCreated.Name == "" || robotCreated.Secret == "" {
		if err := client.DeleteRobotAccountByID(ctx, robotCreated.ID); err == nil || isNotFound(err) {
			b.deleteWAL(ctx, s, walID)
		} else {
			b.Logger().Warn("failed to delete robot account after invalid creation response", "id", robotCreated.ID, "error", err)
		}
		return nil, errors.New("error creating Harbor robot account: invalid response from Harbor")
	}

	// Credentials for an account Vault did not name are credentials no revoke and no WAL rollback
	// can reclaim. The WAL entry is kept: the account Vault asked for may exist, and the description
	// nonce reclaims it whatever Harbor answered.
	if !sameRobotAccount(robotCreated.Name, wal.Name, prefix, wal.Project) {
		return nil, fmt.Errorf("error creating Harbor robot account: Harbor returned the robot account %d named %q instead of %q", robotCreated.ID, robotCreated.Name, wal.Name)
	}

	if err := framework.DeleteWAL(ctx, s, walID); err != nil {
		return nil, fmt.Errorf("error deleting WAL entry: %w", err)
	}

	robotToken := fmt.Sprintf("%s:%s", robotCreated.Name, robotCreated.Secret)

	return &harborRobotAccount{
		ID:        robotCreated.ID,
		Name:      robotCreated.Name,
		Secret:    robotCreated.Secret,
		AuthToken: base64.StdEncoding.EncodeToString([]byte(robotToken)),
	}, nil
}

func (b *harborBackend) deleteWAL(ctx context.Context, s logical.Storage, id string) {
	if err := framework.DeleteWAL(ctx, s, id); err != nil {
		b.Logger().Warn("failed to delete WAL entry", "id", id, "error", err)
	}
}

func newNonce() (string, error) {
	buf := make([]byte, 16)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("error generating nonce: %w", err)
	}
	return hex.EncodeToString(buf), nil
}

// robotDescription ties a robot account to the request that created it, for WAL rollback.
func robotDescription(nonce string) string {
	return fmt.Sprintf("This robot account is created by Vault, please DO NOT edit! (%s)", nonce)
}

// effectiveMaxTTL bounds the role max_ttl by the mount max lease TTL.
func (b *harborBackend) effectiveMaxTTL(role *harborRoleEntry) time.Duration {
	systemMaxTTL := b.System().MaxLeaseTTL()
	if role.MaxTTL > 0 && role.MaxTTL < systemMaxTTL {
		return role.MaxTTL
	}
	return systemMaxTTL
}

// harborDurationDays converts a lease max TTL to Harbor's robot duration in whole days,
// rounded up after adding robotExpiryMargin.
func harborDurationDays(maxTTL time.Duration) int64 {
	d := maxTTL + robotExpiryMargin
	days := int64(d / day)
	if d%day != 0 {
		days++
	}
	if days < 1 {
		days = 1
	}
	return days
}

// robotAccountName builds a robot name of at most maxLen matching Harbor's ^[a-z0-9]+(?:[._-][a-z0-9]+)*$.
func robotAccountName(roleName, displayName string, maxLen int, now time.Time) string {
	parts := []string{"vault", sanitizeRobotNamePart(roleName, robotNameMaxLen)}
	if dn := sanitizeRobotNamePart(displayName, robotNameDisplayMaxLen); dn != "" {
		parts = append(parts, dn)
	}

	prefix := strings.Join(parts, ".")
	if maxPrefixLen := maxLen - robotNameTimestampLen - 1; len(prefix) > maxPrefixLen {
		prefix = strings.TrimRight(prefix[:maxPrefixLen], robotNameSeparators)
	}

	return fmt.Sprintf("%s.%d", prefix, now.UnixNano())
}

func sanitizeRobotNamePart(s string, maxLen int) string {
	s = strings.ToLower(s)
	s = robotNameInvalidChars.ReplaceAllString(s, "-")
	s = robotNameSeparatorsRuns.ReplaceAllStringFunc(s, func(run string) string { return run[:1] })
	s = strings.Trim(s, robotNameSeparators)
	if len(s) > maxLen {
		s = strings.TrimRight(s[:maxLen], robotNameSeparators)
	}
	return s
}
