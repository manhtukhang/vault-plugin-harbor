package harbor

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	harborModel "github.com/mittwald/goharbor-client/v5/apiv2/model"
)

const (
	pathRotateRootHelpSyn  = `Rotate the credentials of the Harbor principal configured in the backend.`
	pathRotateRootHelpDesc = `
A robot account principal is replaced by a new robot account with the same level, duration and
permissions, whose name ends with a new ".r<unix time>" suffix; the previous robot account is
deleted. A local user principal gets a new random password. The new credentials are only stored
in Vault.
`

	rootRobotWALKind = "root_robot"
	rootUserWALKind  = "root_user"

	rootPasswordLength = 32
	rootPasswordChars  = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

var (
	rotationSuffixRegexp = regexp.MustCompile(`\.r[0-9]+$`)
	trailingNamePart     = regexp.MustCompile(`[a-z0-9]+$`)
)

// rootUserWALEntry holds a new user password until it is stored in the config; WAL entries live in
// barrier-encrypted storage.
type rootUserWALEntry struct {
	URL      string `json:"harbor_url"`
	Username string `json:"username"`
	Password string `json:"password"`
}

func pathRotateRoot(b *harborBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config/rotate-root",
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback:                    b.pathRotateRoot,
				ForwardPerformanceStandby:   true,
				ForwardPerformanceSecondary: true,
			},
		},
		HelpSynopsis:    pathRotateRootHelpSyn,
		HelpDescription: pathRotateRootHelpDesc,
	}
}

func (b *harborBackend) pathRotateRoot(ctx context.Context, req *logical.Request, _ *framework.FieldData) (*logical.Response, error) {
	b.configLock.Lock()
	defer b.configLock.Unlock()

	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse("%s", errBackendNotConfigured), nil
	}

	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	robot, err := findRobotPrincipal(ctx, client, config)
	if err != nil {
		return nil, err
	}
	if robot != nil {
		return b.rotateRootRobot(ctx, req.Storage, client, config, robot)
	}

	user, err := client.GetCurrentUser(ctx)
	if err != nil {
		var apiErr *harborAPIError
		if !errors.As(err, &apiErr) || apiErr.StatusCode == http.StatusUnauthorized || apiErr.StatusCode >= http.StatusInternalServerError {
			return nil, fmt.Errorf("error reading the current Harbor user: %w", err)
		}
	}
	if user != nil && user.UserID > 0 && user.Username == config.Username {
		return b.rotateRootUser(ctx, req.Storage, client, config, user.UserID)
	}

	return logical.ErrorResponse("rotate-root requires the configured principal to be a Harbor system robot account with robot create, read, list and delete permissions, or a local Harbor user"), nil
}

// findRobotPrincipal returns the system robot account named config.Username, or nil if there is none.
func findRobotPrincipal(ctx context.Context, client *harborClient, config *harborConfig) (*harborModel.Robot, error) {
	// A fuzzy filter: an exact name= value is unescaped twice by Harbor.
	query := "Level=system"
	if term := robotNameSearchTerm(config.Username, config.RobotPrefix); term != "" {
		query += ",name=~" + term
	}

	robots, err := client.ListRobotAccounts(ctx, query)
	var apiErr *harborAPIError
	if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusForbidden {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("error listing robot accounts: %w", err)
	}

	for _, robot := range robots {
		if robot.Name == config.Username && robot.ID > 0 {
			return client.GetRobotAccountByID(ctx, robot.ID)
		}
	}
	return nil, nil
}

// robotNameSearchTerm returns a substring of the name Harbor stores for the robot, which excludes
// its robot_name_prefix, or "" when that substring cannot be filtered on.
func robotNameSearchTerm(username, prefix string) string {
	var term string
	switch i := strings.LastIndexAny(username, "$+"); {
	case prefix != "" && strings.HasPrefix(username, prefix):
		term = username[len(prefix):]
	case i >= 0:
		term = username[i+1:]
	default:
		term = trailingNamePart.FindString(username)
	}

	// Harbor splits q= on ",", keeps the last value of a repeated key and unescapes a second time,
	// so a term carrying either separator would rewrite the Level and ProjectID of the filter.
	if strings.ContainsAny(term, ",=") {
		return ""
	}
	return term
}

// rotatedRobotName derives the name of the next principal robot account, keeping one ".r<unix time>" suffix.
func rotatedRobotName(username, prefix string, now time.Time) string {
	name := username
	if prefix != "" && strings.HasPrefix(name, prefix) {
		name = name[len(prefix):]
	} else if i := strings.LastIndexAny(name, "$+"); i >= 0 {
		name = name[i+1:]
	}
	name = rotationSuffixRegexp.ReplaceAllString(name, "")

	// Harbor enforces unique(name, project_id) and answers 409, so two rotations within a second
	// must not derive the same name.
	suffix := fmt.Sprintf(".r%d", now.UnixNano())
	name = sanitizeRobotNamePart(name, robotNameMaxLen-len(suffix))
	if name == "" {
		name = "vault"
	}
	return name + suffix
}

func (b *harborBackend) rotateRootRobot(ctx context.Context, s logical.Storage, client *harborClient, config *harborConfig, old *harborModel.Robot) (*logical.Response, error) {
	if old.Level != robotKindSystem {
		return logical.ErrorResponse("rotate-root requires a system robot account, %q is a %s robot account", config.Username, old.Level), nil
	}

	wal := &robotWALEntry{
		Name:  rotatedRobotName(config.Username, config.RobotPrefix, time.Now()),
		URL:   client.url,
		Level: robotKindSystem,
	}
	var err error
	if wal.Nonce, err = newNonce(); err != nil {
		return nil, err
	}

	walID, err := framework.PutWAL(ctx, s, rootRobotWALKind, wal)
	if err != nil {
		return nil, fmt.Errorf("error writing WAL entry: %w", err)
	}

	created, err := client.NewRobotAccount(ctx, &harborModel.RobotCreate{
		Name:        wal.Name,
		Description: robotDescription(wal.Nonce),
		Duration:    old.Duration,
		Level:       old.Level,
		Permissions: old.Permissions,
	})
	if err != nil {
		// An intermediary can answer 4xx for a request Harbor committed, so the WAL entry is kept
		// whatever the outcome; rollback is exact and idempotent through the description nonce.
		return nil, fmt.Errorf("error creating Harbor robot account: %w", err)
	}
	if created == nil || created.ID <= 0 {
		return nil, errors.New("error creating Harbor robot account: invalid response from Harbor")
	}

	discard := func(cause error) (*logical.Response, error) {
		if err := client.DeleteRobotAccountByID(ctx, created.ID); err == nil || isNotFound(err) {
			b.deleteWAL(ctx, s, walID)
		} else {
			b.Logger().Warn("failed to delete new principal robot account", "id", created.ID, "error", err)
		}
		return nil, cause
	}

	if created.Secret == "" {
		return discard(errors.New("error creating Harbor robot account: invalid response from Harbor"))
	}
	if !sameRobotAccount(created.Name, wal.Name, config.RobotPrefix, "") {
		return discard(fmt.Errorf("error creating Harbor robot account: Harbor returned the robot account %d named %q instead of %q", created.ID, created.Name, wal.Name))
	}

	newConfig := *config
	newConfig.Username = created.Name
	newConfig.Password = created.Secret
	newConfig.RobotPrefix = strings.TrimSuffix(created.Name, wal.Name)
	newConfig.RobotID = created.ID

	rotated, err := newClient(&newConfig)
	if err != nil {
		return discard(err)
	}
	defer rotated.http.CloseIdleConnections()

	if err := rotated.verifyConnection(ctx); err != nil {
		return discard(fmt.Errorf("error verifying new robot account %d: %w", created.ID, err))
	}

	if err := storeConfig(ctx, s, &newConfig); err != nil {
		return nil, err
	}
	b.reset()
	b.deleteWAL(ctx, s, walID)

	b.Logger().Info("rotated the Harbor principal robot account", "old_id", old.ID, "id", created.ID, "username", newConfig.Username)

	resp := &logical.Response{Data: map[string]interface{}{"username": newConfig.Username, "robot_id": created.ID}}
	if err := rotated.DeleteRobotAccountByID(ctx, old.ID); err != nil && !isNotFound(err) {
		b.Logger().Warn("failed to delete previous principal robot account", "id", old.ID, "error", err)
		resp.AddWarning(fmt.Sprintf("the configuration uses the new robot account but deleting the previous robot account %d failed, delete it in Harbor: %s", old.ID, err))
	}
	return resp, nil
}

func (b *harborBackend) rotateRootUser(ctx context.Context, s logical.Storage, client *harborClient, config *harborConfig, userID int64) (*logical.Response, error) {
	password, err := newRootPassword()
	if err != nil {
		return nil, err
	}

	walID, err := framework.PutWAL(ctx, s, rootUserWALKind, &rootUserWALEntry{
		URL:      client.url,
		Username: config.Username,
		Password: password,
	})
	if err != nil {
		return nil, fmt.Errorf("error writing WAL entry: %w", err)
	}

	if err := client.UpdateUserPassword(ctx, userID, config.Password, password); err != nil {
		// An intermediary can answer 4xx for a change Harbor applied, so the WAL entry is kept
		// whatever the outcome; the rollback rolls it forward, and drops it only once Harbor has
		// rejected the password it holds.
		var apiErr *harborAPIError
		if errors.As(err, &apiErr) && apiErr.StatusCode >= http.StatusBadRequest && apiErr.StatusCode < http.StatusInternalServerError {
			return logical.ErrorResponse("harbor refused to change the password of user %q (only database users, or the local admin under LDAP/OIDC authentication, can change it): %s", config.Username, err), nil
		}
		return nil, fmt.Errorf("error changing the password of Harbor user %q: %w", config.Username, err)
	}

	newConfig := *config
	newConfig.Password = password
	if err := storeConfig(ctx, s, &newConfig); err != nil {
		return nil, err
	}
	b.reset()
	b.deleteWAL(ctx, s, walID)

	b.Logger().Info("rotated the password of the Harbor principal user", "username", newConfig.Username)

	return &logical.Response{Data: map[string]interface{}{"username": newConfig.Username}}, nil
}

// newRootPassword returns a password satisfying Harbor's policy: 8-128 characters with at least one
// uppercase letter, one lowercase letter and one digit.
func newRootPassword() (string, error) {
	charCount := big.NewInt(int64(len(rootPasswordChars)))
	buf := make([]byte, rootPasswordLength)
	for {
		for i := range buf {
			n, err := rand.Int(rand.Reader, charCount)
			if err != nil {
				return "", fmt.Errorf("error generating password: %w", err)
			}
			buf[i] = rootPasswordChars[n.Int64()]
		}
		if p := string(buf); strings.ContainsAny(p, "abcdefghijklmnopqrstuvwxyz") &&
			strings.ContainsAny(p, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") && strings.ContainsAny(p, "0123456789") {
			return p, nil
		}
	}
}

// rootRobotWALRollback deletes a principal robot account whose rotation did not complete.
func (b *harborBackend) rootRobotWALRollback(ctx context.Context, s logical.Storage, entry *robotWALEntry) error {
	b.configLock.Lock()
	defer b.configLock.Unlock()

	config, err := getConfig(ctx, s)
	if err != nil {
		return err
	}
	return b.deleteWALRobot(ctx, s, entry, config)
}

// isPrincipalRobot reports whether robot is the account the backend authenticates with. The name the
// rotation chose is not enough to tell: config.RobotPrefix is only learned by a successful rotation
// and is lost when the configuration is rewritten, so the resolved id decides, with the stored
// username as a fallback.
func isPrincipalRobot(config *harborConfig, robot *harborModel.Robot) bool {
	if config == nil || robot == nil || robot.Name == "" {
		return false
	}
	if config.RobotID > 0 && config.RobotID == robot.ID {
		return true
	}
	name := unprefixedRobotName(strings.TrimPrefix(config.Username, config.RobotPrefix))
	return sameRobotAccount(robot.Name, name, config.RobotPrefix, "")
}

// rootUserWALRollback stores a user password Harbor may have accepted without Vault storing it.
func (b *harborBackend) rootUserWALRollback(ctx context.Context, s logical.Storage, entry *rootUserWALEntry) error {
	b.configLock.Lock()
	defer b.configLock.Unlock()

	config, err := getConfig(ctx, s)
	if err != nil {
		return err
	}
	if config == nil || config.URL != entry.URL || config.Username != entry.Username || config.Password == entry.Password {
		return nil
	}

	newConfig := *config
	newConfig.Password = entry.Password
	client, err := newClient(&newConfig)
	if err != nil {
		return err
	}
	defer client.http.CloseIdleConnections()

	if _, err := client.GetCurrentUser(ctx); err != nil {
		var apiErr *harborAPIError
		if errors.As(err, &apiErr) && apiErr.StatusCode == http.StatusUnauthorized {
			return nil
		}
		return fmt.Errorf("error checking the rotated password of Harbor user %q: %w", entry.Username, err)
	}

	b.Logger().Warn("Harbor accepted a rotated password that was not stored, storing it", "username", entry.Username)
	if err := storeConfig(ctx, s, &newConfig); err != nil {
		return err
	}
	b.reset()
	return nil
}
