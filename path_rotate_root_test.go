package harbor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"

	harborModel "github.com/mittwald/goharbor-client/v5/apiv2/model"
)

func principalPermissions() []*harborModel.RobotPermission {
	return []*harborModel.RobotPermission{
		{Kind: "system", Namespace: "/", Access: []*harborModel.Access{
			{Resource: "robot", Action: "create"},
			{Resource: "robot", Action: "read"},
			{Resource: "robot", Action: "list"},
			{Resource: "robot", Action: "delete"},
		}},
		{Kind: "project", Namespace: "*", Access: []*harborModel.Access{
			{Resource: "robot", Action: "create"},
			{Resource: "repository", Action: "pull", Effect: "allow"},
		}},
	}
}

func configureBackendAs(t *testing.T, b *harborBackend, s logical.Storage, f *fakeHarbor, username, password string) {
	t.Helper()
	resp, err := configRequest(t, b, s, map[string]interface{}{
		"url":      f.URL(),
		"username": username,
		"password": password,
		"ca_cert":  f.CACert(),
	})
	requireNoError(t, resp, err)
}

// setupRobotPrincipal configures a backend whose principal is the system robot "<prefix>vault".
func setupRobotPrincipal(t *testing.T, prefix string) (*harborBackend, logical.Storage, *fakeHarbor, int64) {
	t.Helper()
	f := newFakeHarbor(t)
	f.setPrefix(prefix)
	id := f.addPrincipalRobot("vault", 30, principalPermissions())
	b, s := getTestBackend(t)
	configureBackendAs(t, b, s, f, prefix+"vault", fakeHarborPassword)
	return b, s, f, id
}

func rotateRoot(b *harborBackend, s logical.Storage) (*logical.Response, error) {
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "config/rotate-root",
		Storage:   s,
	})
}

func storedConfig(t *testing.T, s logical.Storage) *harborConfig {
	t.Helper()
	config, err := getConfig(context.Background(), s)
	require.NoError(t, err)
	require.NotNil(t, config)
	return config
}

func requireNoSecrets(t *testing.T, resp *logical.Response, secrets ...string) {
	t.Helper()
	raw, err := json.Marshal(resp)
	require.NoError(t, err)
	for _, secret := range secrets {
		require.NotContains(t, string(raw), secret)
	}
}

func requireRejectedCredentials(t *testing.T, f *fakeHarbor, username, password string) {
	t.Helper()
	client, err := newClient(&harborConfig{URL: f.URL(), Username: username, Password: password, CACert: f.CACert()})
	require.NoError(t, err)
	var apiErr *harborAPIError
	require.ErrorAs(t, client.verifyConnection(context.Background()), &apiErr)
	require.Equal(t, http.StatusUnauthorized, apiErr.StatusCode)
}

type failingPutStorage struct {
	logical.Storage
	key string
}

func (s *failingPutStorage) Put(ctx context.Context, entry *logical.StorageEntry) error {
	if entry.Key == s.key {
		return errors.New("storage unavailable")
	}
	return s.Storage.Put(ctx, entry)
}

func TestRotateRootRobot(t *testing.T) {
	for prefix, namePattern := range map[string]string{
		"robot$": `^robot\$vault\.r\d+$`,
		"bot-":   `^bot-vault\.r\d+$`,
	} {
		t.Run(prefix, func(t *testing.T) {
			b, s, f, oldID := setupRobotPrincipal(t, prefix)
			if prefix != "robot$" {
				// A system robot's name is not separated from Harbor's robot_name_prefix, so a
				// prefix without "$" has to have been recorded by an earlier rotation.
				setRobotPrefix(t, s, prefix)
			}
			decoy := f.addRobot("xvault", robotKindSystem, 0, "")
			projectTwin := f.addRobot("library+vault", robotKindProject, 1, "")

			resp, err := rotateRoot(b, s)
			requireNoError(t, resp, err)
			requireNoWAL(t, s)
			require.Empty(t, resp.Warnings)

			config := storedConfig(t, s)
			require.Equal(t, map[string]interface{}{"username": config.Username, "robot_id": config.RobotID}, resp.Data)
			require.Positive(t, config.RobotID)
			require.Regexp(t, namePattern, config.Username)
			require.Equal(t, fakeRobotSecret, config.Password)
			require.Equal(t, prefix, config.RobotPrefix)
			requireNoSecrets(t, resp, fakeHarborPassword, fakeRobotSecret)
			require.NotContains(t, readConfig(t, b, s).Data, "robot_prefix")

			create := f.lastCreate()
			require.Equal(t, robotKindSystem, create.Level)
			require.Equal(t, int64(30), create.Duration)
			require.Equal(t, principalPermissions(), create.Permissions)
			require.Equal(t, prefix+create.Name, config.Username)
			require.Regexp(t, `\([0-9a-f]{32}\)$`, create.Description)

			require.Equal(t, []int64{oldID}, f.deletedIDs())
			for _, id := range []int64{decoy, projectTwin} {
				_, found := f.robot(id)
				require.True(t, found)
			}
			requireRejectedCredentials(t, f, prefix+"vault", fakeHarborPassword)

			resp, err = rotateRoot(b, s)
			requireNoError(t, resp, err)
			config = storedConfig(t, s)
			require.Regexp(t, namePattern, config.Username)
			require.Equal(t, prefix, config.RobotPrefix)
			require.Len(t, f.deletedIDs(), 2)
			require.Equal(t, 3, f.robotCount())
			requireNoWAL(t, s)

			resp, err = roleRequest(t, b, s, "ci", map[string]interface{}{"permissions": testProjectPermissions})
			requireNoError(t, resp, err)
			resp, err = readCreds(t, b, s, "ci")
			requireNoError(t, resp, err)
		})
	}
}

func TestRotatedRobotName(t *testing.T) {
	// Harbor enforces unique(name, project_id), so the suffix carries nanoseconds.
	now := time.Unix(0, 1700000000123456789)
	const suffix = ".r1700000000123456789"
	cases := []struct{ username, prefix, want string }{
		{"robot$vault", "", "vault" + suffix},
		{"robot$vault.r1600000000", "robot$", "vault" + suffix},
		{"robot$vault.r1600000000", "", "vault" + suffix},
		{"bot-vault", "", "bot-vault" + suffix},
		{"bot-bot-vault.r1600000000", "bot-", "bot-vault" + suffix},
		{"robot$library+vault", "", "vault" + suffix},
		{"robot$vault.rotate", "", "vault.rotate" + suffix},
		{"robot$", "", "vault" + suffix},
		{"robot$" + strings.Repeat("a", 200), "", strings.Repeat("a", robotNameMaxLen-len(suffix)) + suffix},
	}
	for _, tc := range cases {
		got := rotatedRobotName(tc.username, tc.prefix, now)
		require.Equal(t, tc.want, got, tc.username)
		require.LessOrEqual(t, len(got), robotNameMaxLen)
		require.Regexp(t, harborNameRegexp, got)
	}

	require.Equal(t, "vault", robotNameSearchTerm("robot$vault", ""))
	require.Equal(t, "vault.r1", robotNameSearchTerm("bot-vault.r1", "bot-"))
	require.Equal(t, "vault", robotNameSearchTerm("bot-vault", ""))
	require.Equal(t, "vault", robotNameSearchTerm("robot$library+vault", "other$"))
}

// TestRotateRootRefusesForeignRobotAccount covers a create answered with the name of another robot
// account, which a suffix match would have stored as the new principal.
func TestRotateRootRefusesForeignRobotAccount(t *testing.T) {
	b, s, f, oldID := setupRobotPrincipal(t, "robot$")
	before := storedConfig(t, s)
	f.onCreate = func(w http.ResponseWriter, create *harborModel.RobotCreate) bool {
		id := f.nextID
		f.nextID++
		f.robots[id] = &fakeRobot{
			Robot:  harborModel.Robot{ID: id, Level: create.Level, Description: create.Description},
			stored: create.Name,
			secret: fakeRobotSecret,
		}
		writeJSON(w, http.StatusCreated, &harborModel.RobotCreated{ID: id, Name: "robot$attacker-owned-" + create.Name, Secret: fakeRobotSecret})
		return true
	}

	_, err := rotateRoot(b, s)
	require.ErrorContains(t, err, "instead of")
	require.NotContains(t, err.Error(), fakeRobotSecret)
	require.Equal(t, before, storedConfig(t, s))
	requireNoWAL(t, s)
	require.Equal(t, 1, f.robotCount())
	_, found := f.robot(oldID)
	require.True(t, found)
}

// TestRotateRootUnrecognizedPrefix covers a robot_name_prefix the backend has not recorded: a
// system robot's name is not separated from it, so it cannot be told apart from the name itself.
func TestRotateRootUnrecognizedPrefix(t *testing.T) {
	b, s, f, oldID := setupRobotPrincipal(t, "bot-")
	before := storedConfig(t, s)

	_, err := rotateRoot(b, s)
	require.ErrorContains(t, err, "instead of")
	require.Equal(t, before, storedConfig(t, s))
	requireNoWAL(t, s)
	require.Equal(t, 1, f.robotCount())
	_, found := f.robot(oldID)
	require.True(t, found)
}

func TestIsPrincipalRobot(t *testing.T) {
	robot := func(id int64, name string) *harborModel.Robot { return &harborModel.Robot{ID: id, Name: name} }

	require.True(t, isPrincipalRobot(&harborConfig{RobotID: 7}, robot(7, "robot$renamed-by-hand")))
	require.True(t, isPrincipalRobot(&harborConfig{Username: "robot$vault-prod"}, robot(7, "robot$vault-prod")))
	require.True(t, isPrincipalRobot(&harborConfig{Username: "robot$vault-prod"}, robot(7, "other$vault-prod")), "the prefix may have changed")

	require.False(t, isPrincipalRobot(&harborConfig{Username: "robot$vault-prod"}, robot(7, "robot$d")), "a suffix of the username is another robot account")
	require.False(t, isPrincipalRobot(&harborConfig{Username: "robot$vault"}, robot(7, "robot$attacker-owned-vault")))
	require.False(t, isPrincipalRobot(&harborConfig{RobotID: 7, Username: "robot$vault"}, robot(9, "robot$other")))
	require.False(t, isPrincipalRobot(&harborConfig{}, robot(7, "robot$vault")))
	require.False(t, isPrincipalRobot(nil, robot(7, "robot$vault")))
	require.False(t, isPrincipalRobot(&harborConfig{Username: "robot$vault"}, nil))
}

// TestFindRobotPrincipalQuery covers Harbor's q= grammar: it splits on ",", keeps the last value of
// a repeated key and unescapes a second time, so a term carrying "," or "=" would rewrite the
// Level of the filter and list robot accounts of another scope.
func TestFindRobotPrincipalQuery(t *testing.T) {
	const poisoned = `robot$vault,Level=project,ProjectID=1`

	require.Empty(t, robotNameSearchTerm(poisoned, ""))
	require.Empty(t, robotNameSearchTerm("bot-vault,Level=project", "bot-"))

	var mu sync.Mutex
	var queries []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == harborAPIPath+"/robots" {
			mu.Lock()
			queries = append(queries, r.URL.Query().Get("q"))
			mu.Unlock()
			writeJSON(w, http.StatusOK, []*harborModel.Robot{{ID: 7, Name: poisoned, Level: robotKindSystem}})
			return
		}
		writeJSON(w, http.StatusOK, &harborModel.Robot{ID: 7, Name: poisoned, Level: robotKindSystem})
	}))
	t.Cleanup(server.Close)

	client, err := newClient(&harborConfig{URL: server.URL, Username: poisoned, Password: fakeHarborPassword})
	require.NoError(t, err)
	defer client.http.CloseIdleConnections()

	robot, err := findRobotPrincipal(context.Background(), client, &harborConfig{Username: poisoned})
	require.NoError(t, err)
	require.NotNil(t, robot)

	mu.Lock()
	defer mu.Unlock()
	require.Equal(t, []string{"Level=system"}, queries, "an unusable term falls back to listing without a name filter")
}

func TestRotateRootLogging(t *testing.T) {
	t.Run("robot principal", func(t *testing.T) {
		f := newFakeHarbor(t)
		oldID := f.addPrincipalRobot("vault", 30, principalPermissions())
		b, s, logs := getTestBackendWithLogs(t)
		configureBackendAs(t, b, s, f, "robot$vault", fakeHarborPassword)

		resp, err := rotateRoot(b, s)
		requireNoError(t, resp, err)

		out := logs.String()
		require.Contains(t, out, "rotated the Harbor principal robot account")
		require.Contains(t, out, fmt.Sprintf("old_id=%d", oldID))
		require.Contains(t, out, fmt.Sprintf("id=%d", resp.Data["robot_id"]))
		require.Contains(t, out, storedConfig(t, s).Username)
		requireNoLoggedSecrets(t, logs, f)
	})

	t.Run("user principal", func(t *testing.T) {
		f := newFakeHarbor(t)
		id := f.addUser("vault-admin", "User-Password-1")
		b, s, logs := getTestBackendWithLogs(t)
		configureBackendAs(t, b, s, f, "vault-admin", "User-Password-1")

		resp, err := rotateRoot(b, s)
		requireNoError(t, resp, err)

		out := logs.String()
		require.Contains(t, out, "rotated the password of the Harbor principal user")
		require.Contains(t, out, "username=vault-admin")
		require.NotContains(t, out, "User-Password-1")
		require.NotContains(t, out, f.userPassword(id))
		requireNoLoggedSecrets(t, logs, f)
	})
}

func TestRotateRootRobotCreateFails(t *testing.T) {
	b, s, f, oldID := setupRobotPrincipal(t, "robot$")
	before := storedConfig(t, s)
	f.onCreate = func(w http.ResponseWriter, _ *harborModel.RobotCreate) bool {
		writeHarborError(w, http.StatusForbidden, "permission scope is invalid")
		return true
	}

	_, err := rotateRoot(b, s)
	require.ErrorContains(t, err, "permission scope is invalid")
	require.NotContains(t, err.Error(), fakeHarborPassword)
	require.Equal(t, before, storedConfig(t, s))

	keys, err := framework.ListWAL(context.Background(), s)
	require.NoError(t, err)
	require.Len(t, keys, 1, "a 4xx never proves that Harbor created nothing")

	f.onCreate = nil
	resp, err := rollback(t, b, s)
	requireNoError(t, resp, err)
	requireNoWAL(t, s)
	_, found := f.robot(oldID)
	require.True(t, found)
	require.Empty(t, f.deletedIDs())
}

func TestRotateRootRobotVerifyFails(t *testing.T) {
	b, s, f, oldID := setupRobotPrincipal(t, "robot$")
	before := storedConfig(t, s)
	f.onCreate = func(w http.ResponseWriter, create *harborModel.RobotCreate) bool {
		id := f.nextID
		f.nextID++
		f.robots[id] = &fakeRobot{
			Robot:  harborModel.Robot{ID: id, Level: create.Level, Description: create.Description},
			stored: create.Name,
			secret: fakeRobotSecret,
		}
		writeJSON(w, http.StatusCreated, &harborModel.RobotCreated{ID: id, Name: f.prefix + create.Name, Secret: "Not-The-Secret-1"})
		return true
	}

	_, err := rotateRoot(b, s)
	require.ErrorContains(t, err, "HTTP 401")
	require.NotContains(t, err.Error(), "Not-The-Secret-1")
	require.Equal(t, before, storedConfig(t, s))
	requireNoWAL(t, s)
	require.Equal(t, 1, f.robotCount())
	_, found := f.robot(oldID)
	require.True(t, found)
}

func TestRotateRootRobotOldDeleteFails(t *testing.T) {
	b, s, f, oldID := setupRobotPrincipal(t, "robot$")
	f.onDelete = func(w http.ResponseWriter, id int64) bool {
		if id != oldID {
			return false
		}
		writeHarborError(w, http.StatusInternalServerError, "database unavailable")
		return true
	}

	resp, err := rotateRoot(b, s)
	requireNoError(t, resp, err)
	require.Len(t, resp.Warnings, 1)
	require.Contains(t, resp.Warnings[0], "robot account 1 failed")
	requireNoSecrets(t, resp, fakeHarborPassword, fakeRobotSecret)

	config := storedConfig(t, s)
	require.Equal(t, resp.Data["username"], config.Username)
	require.Equal(t, fakeRobotSecret, config.Password)
	_, found := f.robot(oldID)
	require.True(t, found)
	requireNoWAL(t, s)
}

func TestRotateRootRobotStorageFailure(t *testing.T) {
	b, s, f, oldID := setupRobotPrincipal(t, "robot$")
	before := storedConfig(t, s)

	_, err := rotateRoot(b, &failingPutStorage{Storage: s, key: configStoragePath})
	require.ErrorContains(t, err, "storage unavailable")
	require.Equal(t, before, storedConfig(t, s))
	require.Equal(t, 2, f.robotCount())
	keys, err := framework.ListWAL(context.Background(), s)
	require.NoError(t, err)
	require.Len(t, keys, 1)

	resp, err := rollback(t, b, s)
	requireNoError(t, resp, err)
	requireNoWAL(t, s)
	require.Equal(t, 1, f.robotCount())
	_, found := f.robot(oldID)
	require.True(t, found)
	require.Equal(t, before, storedConfig(t, s))
}

// putRotationWAL replays the WAL entry of the rotation that created the configured principal.
func putRotationWAL(t *testing.T, s logical.Storage, f *fakeHarbor) {
	t.Helper()
	create := f.lastCreate()
	nonce := regexp.MustCompile(`\(([0-9a-f]{32})\)$`).FindStringSubmatch(create.Description)[1]
	_, err := framework.PutWAL(context.Background(), s, rootRobotWALKind, &robotWALEntry{
		Name:  create.Name,
		Nonce: nonce,
		URL:   f.URL(),
		Level: robotKindSystem,
	})
	require.NoError(t, err)
}

func TestRotateRootRobotRollbackAfterSwitch(t *testing.T) {
	b, s, f, _ := setupRobotPrincipal(t, "robot$")
	resp, err := rotateRoot(b, s)
	requireNoError(t, resp, err)
	config := storedConfig(t, s)

	putRotationWAL(t, s, f)

	resp, err = rollback(t, b, s)
	requireNoError(t, resp, err)
	requireNoWAL(t, s)
	require.Equal(t, 1, f.robotCount())
	require.Len(t, f.deletedIDs(), 1)
	require.Equal(t, config, storedConfig(t, s))
}

// TestRotateRootRollbackKeepsLivePrincipal replays the rotation WAL entry against a configuration
// that was rewritten afterwards, where the name of the principal can no longer be reconstructed.
func TestRotateRootRollbackKeepsLivePrincipal(t *testing.T) {
	rewriteConfig := func(t *testing.T, b *harborBackend, s logical.Storage, f *fakeHarbor, config *harborConfig, verifyConnection bool) {
		t.Helper()
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      configStoragePath,
			Storage:   s,
		})
		requireNoError(t, resp, err)

		resp, err = configRequest(t, b, s, map[string]interface{}{
			"url":               f.URL(),
			"username":          config.Username,
			"password":          config.Password,
			"ca_cert":           f.CACert(),
			"verify_connection": verifyConnection,
		})
		requireNoError(t, resp, err)
	}

	for name, verifyConnection := range map[string]bool{"principal resolved": true, "principal unresolved": false} {
		t.Run(name, func(t *testing.T) {
			b, s, f, oldID := setupRobotPrincipal(t, "robot$")

			resp, err := rotateRoot(b, s)
			requireNoError(t, resp, err)
			rotated := storedConfig(t, s)
			require.Positive(t, rotated.RobotID)
			require.Equal(t, []int64{oldID}, f.deletedIDs())

			rewriteConfig(t, b, s, f, rotated, verifyConnection)
			config := storedConfig(t, s)
			require.Empty(t, config.RobotPrefix)
			require.Equal(t, rotated.Username, config.Username)
			if verifyConnection {
				require.Equal(t, rotated.RobotID, config.RobotID)
			} else {
				require.Zero(t, config.RobotID)
			}
			require.NotContains(t, readConfig(t, b, s).Data, "robot_id")

			putRotationWAL(t, s, f)
			resp, err = rollback(t, b, s)
			requireNoError(t, resp, err)
			requireNoWAL(t, s)

			require.Equal(t, []int64{oldID}, f.deletedIDs(), "the live principal must survive the rollback")
			_, found := f.robot(rotated.RobotID)
			require.True(t, found)

			resp, err = roleRequest(t, b, s, "ci", map[string]interface{}{"permissions": testProjectPermissions})
			requireNoError(t, resp, err)
			resp, err = readCreds(t, b, s, "ci")
			requireNoError(t, resp, err)
		})
	}

	t.Run("orphan", func(t *testing.T) {
		const nonce = "0123456789abcdef0123456789abcdef"
		b, s, f, oldID := setupRobotPrincipal(t, "robot$")

		resp, err := rotateRoot(b, s)
		requireNoError(t, resp, err)
		config := storedConfig(t, s)

		orphan := f.addRobot("vault.r1600000000000000000", robotKindSystem, 0, robotDescription(nonce))
		_, err = framework.PutWAL(context.Background(), s, rootRobotWALKind, &robotWALEntry{
			Name:  "vault.r1600000000000000000",
			Nonce: nonce,
			URL:   f.URL(),
			Level: robotKindSystem,
		})
		require.NoError(t, err)

		resp, err = rollback(t, b, s)
		requireNoError(t, resp, err)
		requireNoWAL(t, s)
		require.Equal(t, []int64{oldID, orphan}, f.deletedIDs())
		require.Equal(t, config, storedConfig(t, s))
		_, found := f.robot(config.RobotID)
		require.True(t, found)
	})

	t.Run("url change clears the principal", func(t *testing.T) {
		b, s, f, _ := setupRobotPrincipal(t, "robot$")
		resp, err := rotateRoot(b, s)
		requireNoError(t, resp, err)
		require.Positive(t, storedConfig(t, s).RobotID)

		other := newFakeHarbor(t)
		resp, err = configRequest(t, b, s, map[string]interface{}{
			"url":               other.URL(),
			"password":          fakeHarborPassword,
			"ca_cert":           other.CACert(),
			"verify_connection": false,
		})
		requireNoError(t, resp, err)

		config := storedConfig(t, s)
		require.Zero(t, config.RobotID)
		require.Empty(t, config.RobotPrefix)
		require.NotEqual(t, f.URL(), config.URL)
	})
}

func setupUserPrincipal(t *testing.T) (*harborBackend, logical.Storage, *fakeHarbor, int64) {
	t.Helper()
	f := newFakeHarbor(t)
	id := f.addUser("vault-admin", "User-Password-1")
	b, s := getTestBackend(t)
	configureBackendAs(t, b, s, f, "vault-admin", "User-Password-1")
	return b, s, f, id
}

func TestRotateRootUser(t *testing.T) {
	b, s, f, id := setupUserPrincipal(t)

	resp, err := rotateRoot(b, s)
	requireNoError(t, resp, err)
	require.Equal(t, map[string]interface{}{"username": "vault-admin"}, resp.Data)
	requireNoWAL(t, s)

	config := storedConfig(t, s)
	require.Equal(t, "vault-admin", config.Username)
	require.Len(t, config.Password, rootPasswordLength)
	require.True(t, fakePasswordPolicy(config.Password))
	require.Equal(t, config.Password, f.userPassword(id))
	requireNoSecrets(t, resp, "User-Password-1", config.Password)

	require.Equal(t, []*harborModel.PasswordReq{{OldPassword: "User-Password-1", NewPassword: config.Password}}, f.passwordRequests())
	require.Contains(t, f.requestLog(), "PUT /api/v2.0/users/1/password")
	requireRejectedCredentials(t, f, "vault-admin", "User-Password-1")

	resp, err = roleRequest(t, b, s, "ci", map[string]interface{}{"permissions": testProjectPermissions})
	requireNoError(t, resp, err)
	resp, err = readCreds(t, b, s, "ci")
	requireNoError(t, resp, err)
}

func TestRotateRootUserFailure(t *testing.T) {
	t.Run("refused", func(t *testing.T) {
		b, s, f, id := setupUserPrincipal(t)
		before := storedConfig(t, s)
		f.onPassword = func(w http.ResponseWriter, _ *harborModel.PasswordReq) bool {
			writeHarborError(w, http.StatusForbidden, "User with ID 1 can't be updated")
			return true
		}

		resp, err := rotateRoot(b, s)
		requireErrorResponse(t, resp, err, "can't be updated")
		requireNoSecrets(t, resp, "User-Password-1", f.passwordRequests()[0].NewPassword)
		require.Equal(t, before, storedConfig(t, s))
		require.Equal(t, "User-Password-1", f.userPassword(id))

		keys, err := framework.ListWAL(context.Background(), s)
		require.NoError(t, err)
		require.Len(t, keys, 1, "a 4xx never proves that Harbor changed nothing")

		// Harbor rejects the password of the WAL entry, so the rollback drops it.
		resp, err = rollback(t, b, s)
		requireNoError(t, resp, err)
		requireNoWAL(t, s)
		require.Equal(t, before, storedConfig(t, s))
		require.Equal(t, "User-Password-1", f.userPassword(id))
	})

	// An intermediary can answer 4xx for a change Harbor applied: Vault would keep the old password
	// while Harbor holds the new one.
	for _, status := range []int{http.StatusTooManyRequests, http.StatusRequestTimeout} {
		t.Run("applied then "+http.StatusText(status), func(t *testing.T) {
			b, s, f, id := setupUserPrincipal(t)
			before := storedConfig(t, s)
			f.onPassword = func(w http.ResponseWriter, req *harborModel.PasswordReq) bool {
				f.users[id].password = req.NewPassword
				writeHarborError(w, status, http.StatusText(status))
				return true
			}

			resp, err := rotateRoot(b, s)
			requireErrorResponse(t, resp, err, "refused to change the password")
			applied := f.passwordRequests()[0].NewPassword
			requireNoSecrets(t, resp, "User-Password-1", applied)
			require.Equal(t, before, storedConfig(t, s))
			require.Equal(t, applied, f.userPassword(id), "Harbor applied the change")

			keys, err := framework.ListWAL(context.Background(), s)
			require.NoError(t, err)
			require.Len(t, keys, 1)

			resp, err = rollback(t, b, s)
			requireNoError(t, resp, err)
			requireNoWAL(t, s)
			require.Equal(t, applied, storedConfig(t, s).Password, "the rollback rolls the rotation forward")
			requireRejectedCredentials(t, f, "vault-admin", "User-Password-1")

			resp, err = roleRequest(t, b, s, "ci", map[string]interface{}{"permissions": testProjectPermissions})
			requireNoError(t, resp, err)
			resp, err = readCreds(t, b, s, "ci")
			requireNoError(t, resp, err)
		})
	}

	t.Run("unknown outcome keeps WAL", func(t *testing.T) {
		b, s, f, _ := setupUserPrincipal(t)
		before := storedConfig(t, s)
		f.onPassword = func(w http.ResponseWriter, _ *harborModel.PasswordReq) bool {
			writeHarborError(w, http.StatusBadGateway, "proxy timeout")
			return true
		}

		_, err := rotateRoot(b, s)
		require.ErrorContains(t, err, "HTTP 502")
		require.NotContains(t, err.Error(), f.passwordRequests()[0].NewPassword)
		require.Equal(t, before, storedConfig(t, s))
		keys, err := framework.ListWAL(context.Background(), s)
		require.NoError(t, err)
		require.Len(t, keys, 1)

		resp, err := rollback(t, b, s)
		requireNoError(t, resp, err)
		requireNoWAL(t, s)
		require.Equal(t, before, storedConfig(t, s))
	})
}

func TestRotateRootUserWALRollback(t *testing.T) {
	putUserWAL := func(t *testing.T, s logical.Storage, entry *rootUserWALEntry) {
		t.Helper()
		_, err := framework.PutWAL(context.Background(), s, rootUserWALKind, entry)
		require.NoError(t, err)
	}

	t.Run("roll forward", func(t *testing.T) {
		b, s, f, id := setupUserPrincipal(t)
		f.mu.Lock()
		f.users[id].password = "Applied-Password-2"
		f.mu.Unlock()

		putUserWAL(t, s, &rootUserWALEntry{URL: f.URL(), Username: "vault-admin", Password: "Applied-Password-2"})
		resp, err := rollback(t, b, s)
		requireNoError(t, resp, err)
		requireNoWAL(t, s)
		require.Equal(t, "Applied-Password-2", storedConfig(t, s).Password)

		resp, err = roleRequest(t, b, s, "ci", map[string]interface{}{"permissions": testProjectPermissions})
		requireNoError(t, resp, err)
		resp, err = readCreds(t, b, s, "ci")
		requireNoError(t, resp, err)
	})

	t.Run("drop", func(t *testing.T) {
		b, s, f, _ := setupUserPrincipal(t)
		before := storedConfig(t, s)

		putUserWAL(t, s, &rootUserWALEntry{URL: f.URL(), Username: "vault-admin", Password: "Rejected-Password-3"})
		putUserWAL(t, s, &rootUserWALEntry{URL: "https://other.example.com", Username: "vault-admin", Password: "Other-Password-4"})
		putUserWAL(t, s, &rootUserWALEntry{URL: f.URL(), Username: "vault-admin", Password: before.Password})
		requests := len(f.requestLog())

		resp, err := rollback(t, b, s)
		requireNoError(t, resp, err)
		requireNoWAL(t, s)
		require.Equal(t, before, storedConfig(t, s))
		require.Len(t, f.requestLog(), requests+1)
	})
}

func TestRotateRootUnsupportedPrincipal(t *testing.T) {
	f := newFakeHarbor(t)
	b, s := getTestBackend(t)

	resp, err := rotateRoot(b, s)
	requireErrorResponse(t, resp, err, "not configured")

	configureBackend(t, b, s, f)
	before := storedConfig(t, s)
	resp, err = rotateRoot(b, s)
	requireErrorResponse(t, resp, err, "rotate-root requires")
	require.Equal(t, before, storedConfig(t, s))
	require.Nil(t, f.lastCreate())
	requireNoWAL(t, s)
}

func TestRotateRootBlocksConfigWrite(t *testing.T) {
	b, s, f, _ := setupRobotPrincipal(t, "robot$")
	started := make(chan struct{})
	release := make(chan struct{})
	f.onCreate = func(http.ResponseWriter, *harborModel.RobotCreate) bool {
		close(started)
		<-release
		return false
	}

	rotated := make(chan error, 1)
	go func() {
		resp, err := rotateRoot(b, s)
		if err == nil && resp.IsError() {
			err = resp.Error()
		}
		rotated <- err
	}()
	<-started

	written := make(chan error, 1)
	go func() {
		_, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.UpdateOperation,
			Path:      configStoragePath,
			Storage:   s,
			Data:      map[string]interface{}{"password": "Written-Password-5", "verify_connection": false},
		})
		written <- err
	}()

	select {
	case <-written:
		t.Fatal("config write did not wait for rotate-root")
	case <-time.After(100 * time.Millisecond):
	}
	close(release)

	require.NoError(t, <-rotated)
	require.NoError(t, <-written)
	config := storedConfig(t, s)
	require.Regexp(t, `^robot\$vault\.r\d+$`, config.Username)
	require.Equal(t, "Written-Password-5", config.Password)
}

func TestRotateRootOperations(t *testing.T) {
	b, s := getTestBackend(t)
	for _, op := range []logical.Operation{logical.ReadOperation, logical.DeleteOperation} {
		_, err := b.HandleRequest(context.Background(), &logical.Request{Operation: op, Path: "config/rotate-root", Storage: s})
		require.ErrorIs(t, err, logical.ErrUnsupportedOperation, op)
	}

	props := pathRotateRoot(b).Operations[logical.UpdateOperation].Properties()
	require.True(t, props.ForwardPerformanceStandby)
	require.True(t, props.ForwardPerformanceSecondary)
}
