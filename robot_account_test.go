package harbor

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"regexp"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/jsonutil"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"

	harborModel "github.com/mittwald/goharbor-client/v5/apiv2/model"
)

// roundTripSecret mimics Vault persisting a lease: InternalData numbers come back as json.Number.
func roundTripSecret(t *testing.T, secret *logical.Secret) *logical.Secret {
	t.Helper()
	raw, err := json.Marshal(secret.InternalData)
	require.NoError(t, err)
	var internal map[string]interface{}
	require.NoError(t, jsonutil.DecodeJSON(raw, &internal))
	copied := *secret
	copied.InternalData = internal
	return &copied
}

func TestRevokeRefusesMismatch(t *testing.T) {
	ctx := context.Background()

	// A robot account renamed around the name Vault chose is another account, which a suffix match
	// would have deleted.
	for name, rename := range map[string]func(robotName string) string{
		"other name":    func(string) string { return "library+someone-else" },
		"name extended": func(robotName string) string { return "library+attacker-owned-" + robotName },
	} {
		t.Run(name, func(t *testing.T) {
			b, s, f := setupCredsBackend(t, 48*time.Hour, testProjectPermissions, nil)
			resp, err := readCreds(t, b, s, "ci")
			requireNoError(t, resp, err)
			id := resp.Data["robot_account_id"].(int64)
			robotName := resp.Secret.InternalData["robot_name"].(string)

			stored := rename(robotName)
			f.renameRobot(id, stored)
			_, err = b.HandleRequest(ctx, &logical.Request{Operation: logical.RevokeOperation, Storage: s, Secret: roundTripSecret(t, resp.Secret)})
			require.ErrorContains(t, err, fmt.Sprintf("robot account %d is named %q instead of %q, refusing to delete", id, "robot$"+stored, robotName))
			_, found := f.robot(id)
			require.True(t, found)
			require.Empty(t, f.deletedIDs())
		})
	}

	t.Run("harbor url", func(t *testing.T) {
		b, s, f := setupCredsBackend(t, 48*time.Hour, testProjectPermissions, nil)
		other := newFakeHarbor(t)
		resp, err := readCreds(t, b, s, "ci")
		requireNoError(t, resp, err)
		id := resp.Data["robot_account_id"].(int64)
		other.addRobot("library+"+resp.Secret.InternalData["robot_name"].(string), robotKindProject, 1, "")

		cfgResp, err := configRequest(t, b, s, map[string]interface{}{"url": other.URL(), "password": fakeHarborPassword})
		requireNoError(t, cfgResp, err)

		_, err = b.HandleRequest(ctx, &logical.Request{Operation: logical.RevokeOperation, Storage: s, Secret: resp.Secret})
		require.ErrorContains(t, err, "refusing to revoke")
		_, found := f.robot(id)
		require.True(t, found)
		require.Empty(t, other.deletedIDs())
	})
}

func TestRevokeInvalidInternalData(t *testing.T) {
	b, s, f := setupCredsBackend(t, 48*time.Hour, testProjectPermissions, nil)
	valid := map[string]interface{}{
		"secret_type":        harborRobotAccountType,
		"role":               "ci",
		"robot_account_id":   int64(1),
		"robot_account_name": "robot$vault.ci.1",
		"harbor_url":         f.URL(),
		"max_ttl":            int64(60),
	}

	requests := len(f.requestLog())
	for _, key := range []string{"robot_account_id", "robot_account_name", "harbor_url"} {
		for name, value := range map[string]interface{}{"missing": nil, "wrong type": []string{"x"}, "empty": ""} {
			internal := map[string]interface{}{}
			for k, v := range valid {
				internal[k] = v
			}
			if value == nil {
				delete(internal, key)
			} else {
				internal[key] = value
			}
			_, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: logical.RevokeOperation,
				Storage:   s,
				Secret:    &logical.Secret{InternalData: internal},
			})
			require.Error(t, err, "%s %s", key, name)
			require.Contains(t, err.Error(), key)
		}
	}
	require.Len(t, f.requestLog(), requests, "no Harbor call beyond config verification")
}

func TestRenewCapsMaxTTL(t *testing.T) {
	b, s, _ := setupCredsBackend(t, 48*time.Hour, testProjectPermissions, map[string]interface{}{"ttl": "1h", "max_ttl": "10h"})
	ctx := context.Background()

	resp, err := readCreds(t, b, s, "ci")
	requireNoError(t, resp, err)
	secret := roundTripSecret(t, resp.Secret)

	renew := func() *logical.Response {
		resp, err := b.HandleRequest(ctx, &logical.Request{Operation: logical.RenewOperation, Storage: s, Secret: secret})
		requireNoError(t, resp, err)
		return resp
	}

	resp = renew()
	require.Equal(t, time.Hour, resp.Secret.TTL)
	require.Equal(t, 10*time.Hour, resp.Secret.MaxTTL)

	roleResp, err := roleRequest(t, b, s, "ci", map[string]interface{}{"max_ttl": "20h", "ttl": "2h"})
	requireNoError(t, roleResp, err)
	resp = renew()
	require.Equal(t, 2*time.Hour, resp.Secret.TTL)
	require.Equal(t, 10*time.Hour, resp.Secret.MaxTTL, "renew must not outlive the Harbor robot")

	roleResp, err = roleRequest(t, b, s, "ci", map[string]interface{}{"max_ttl": "5h"})
	requireNoError(t, roleResp, err)
	resp = renew()
	require.Equal(t, 5*time.Hour, resp.Secret.MaxTTL)

	delete(secret.InternalData, "max_ttl")
	_, err = b.HandleRequest(ctx, &logical.Request{Operation: logical.RenewOperation, Storage: s, Secret: secret})
	require.ErrorContains(t, err, "max_ttl")

	secret.InternalData["max_ttl"] = int64(60)
	secret.InternalData["role"] = 42
	_, err = b.HandleRequest(ctx, &logical.Request{Operation: logical.RenewOperation, Storage: s, Secret: secret})
	require.ErrorContains(t, err, "role")

	secret.InternalData["role"] = "deleted"
	resp, err = b.HandleRequest(ctx, &logical.Request{Operation: logical.RenewOperation, Storage: s, Secret: secret})
	requireNoError(t, resp, err)
	require.Equal(t, time.Minute, resp.Secret.MaxTTL, "a deleted role still renews within the stored max_ttl")
}

func TestLeaseInt64(t *testing.T) {
	valid := []interface{}{int64(5), 5, float64(5), json.Number("5"), "5"}
	for _, v := range valid {
		got, err := leaseInt64(map[string]interface{}{"k": v}, "k")
		require.NoError(t, err, "%T", v)
		require.Equal(t, int64(5), got)
	}

	invalid := []interface{}{float64(5.5), json.Number("5.5"), "x", int64(0), -1, true, nil, float64(1e30)}
	for _, v := range invalid {
		_, err := leaseInt64(map[string]interface{}{"k": v}, "k")
		require.Error(t, err, "%T %v", v, v)
	}

	_, err := leaseInt64(map[string]interface{}{}, "k")
	require.ErrorContains(t, err, "missing")
}

func putRobotWAL(t *testing.T, s logical.Storage, entry *robotWALEntry) {
	t.Helper()
	_, err := framework.PutWAL(context.Background(), s, robotWALKind, entry)
	require.NoError(t, err)
}

func rollback(t *testing.T, b *harborBackend, s logical.Storage) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.RollbackOperation,
		Storage:   s,
		Data:      map[string]interface{}{"immediate": true},
	})
}

func TestWALRollback(t *testing.T) {
	const nonce = "0123456789abcdef0123456789abcdef"
	const otherNonce = "fedcba9876543210fedcba9876543210"

	for _, prefix := range []string{"robot$", "robot_", "bot-"} {
		t.Run("system robot among many with prefix "+prefix, func(t *testing.T) {
			f := newFakeHarbor(t)
			f.setPrefix(prefix)
			b, s := getTestBackend(t)
			configureBackend(t, b, s, f)
			if prefix != "robot$" {
				// A system robot's name is not separated from Harbor's robot_name_prefix, so a
				// prefix without "$" has to have been recorded by an earlier rotation.
				setRobotPrefix(t, s, prefix)
			}

			for i := 0; i < 150; i++ {
				f.addRobot(fmt.Sprintf("vault.ci.other%d", i), robotKindSystem, 0, robotDescription(nonce))
			}
			target := f.addRobot("vault.ci.1700000000000000000", robotKindSystem, 0, robotDescription(nonce))
			decoy := f.addRobot("xvault.ci.1700000000000000000", robotKindSystem, 0, robotDescription(otherNonce))
			sameNameOtherRequest := f.addRobot("vault.ci.1700000000000000000", robotKindSystem, 0, robotDescription(otherNonce))
			projectTwin := f.addRobot("library+vault.ci.1700000000000000000", robotKindProject, 1, robotDescription(nonce))
			renamed := f.addRobot("attacker-owned-vault.ci.1700000000000000000", robotKindSystem, 0, robotDescription(nonce))

			putRobotWAL(t, s, &robotWALEntry{Name: "vault.ci.1700000000000000000", Nonce: nonce, URL: f.URL(), Level: robotKindSystem})
			resp, err := rollback(t, b, s)
			requireNoError(t, resp, err)

			require.Equal(t, []int64{target}, f.deletedIDs())
			for _, id := range []int64{decoy, sameNameOtherRequest, projectTwin, renamed} {
				_, found := f.robot(id)
				require.True(t, found, "a robot account named around the one Vault chose is another account")
			}
			requireNoWAL(t, s)
		})

		t.Run("project robot with prefix "+prefix, func(t *testing.T) {
			f := newFakeHarbor(t)
			f.setPrefix(prefix)
			b, s := getTestBackend(t)
			configureBackend(t, b, s, f)

			target := f.addRobot("library+vault.ci.1", robotKindProject, 1, robotDescription(nonce))
			other := f.addRobot("library+vault.ci.1", robotKindProject, 1, robotDescription(otherNonce))
			renamed := f.addRobot("library+attacker-owned-vault.ci.1", robotKindProject, 1, robotDescription(nonce))
			putRobotWAL(t, s, &robotWALEntry{Name: "vault.ci.1", Nonce: nonce, URL: f.URL(), Level: robotKindProject, Project: "library"})
			putRobotWAL(t, s, &robotWALEntry{Name: "vault.ci.2", Nonce: nonce, URL: f.URL(), Level: robotKindProject, Project: "deleted-project"})

			resp, err := rollback(t, b, s)
			requireNoError(t, resp, err)
			require.Equal(t, []int64{target}, f.deletedIDs())
			for _, id := range []int64{other, renamed} {
				_, found := f.robot(id)
				require.True(t, found)
			}
			requireNoWAL(t, s)
		})
	}

	t.Run("robot created by a failed request", func(t *testing.T) {
		b, s, f := setupCredsBackend(t, 48*time.Hour, testProjectPermissions, nil)
		f.setPrefix("bot-")
		f.onCreate = func(w http.ResponseWriter, create *harborModel.RobotCreate) bool {
			f.robots[f.nextID] = &fakeRobot{
				Robot:     harborModel.Robot{ID: f.nextID, Level: create.Level, Description: create.Description},
				stored:    "library+" + create.Name,
				projectID: 1,
			}
			f.nextID++
			writeHarborError(w, http.StatusBadGateway, "proxy timeout")
			return true
		}
		_, err := readCreds(t, b, s, "ci")
		require.Error(t, err)
		require.Equal(t, 1, f.robotCount())

		resp, err := rollback(t, b, s)
		requireNoError(t, resp, err)
		require.Zero(t, f.robotCount())
		requireNoWAL(t, s)
	})

	t.Run("absent robot, other harbor, unconfigured, no nonce", func(t *testing.T) {
		f := newFakeHarbor(t)
		b, s := getTestBackend(t)
		putRobotWAL(t, s, &robotWALEntry{Name: "vault.ci.1", Nonce: nonce, URL: f.URL(), Level: robotKindSystem})
		resp, err := rollback(t, b, s)
		requireNoError(t, resp, err)
		requireNoWAL(t, s)

		configureBackend(t, b, s, f)
		id := f.addRobot("vault.ci.1", robotKindSystem, 0, robotDescription(nonce))
		putRobotWAL(t, s, &robotWALEntry{Name: "vault.ci.1", Nonce: nonce, URL: "https://other.example.com", Level: robotKindSystem})
		putRobotWAL(t, s, &robotWALEntry{Name: "vault.ci.1", URL: f.URL(), Level: robotKindSystem})
		putRobotWAL(t, s, &robotWALEntry{Name: "vault.ci.404", Nonce: nonce, URL: f.URL(), Level: robotKindSystem})
		resp, err = rollback(t, b, s)
		requireNoError(t, resp, err)
		_, found := f.robot(id)
		require.True(t, found)
		require.Empty(t, f.deletedIDs())
		requireNoWAL(t, s)
	})

	t.Run("harbor failure keeps WAL", func(t *testing.T) {
		f := newFakeHarbor(t)
		b, s := getTestBackend(t)
		configureBackend(t, b, s, f)
		f.server.Close()

		putRobotWAL(t, s, &robotWALEntry{Name: "vault.ci.1", Nonce: nonce, URL: f.URL(), Level: robotKindSystem})
		resp, err := rollback(t, b, s)
		require.True(t, err != nil || (resp != nil && resp.IsError()))
		keys, err := framework.ListWAL(context.Background(), s)
		require.NoError(t, err)
		require.Len(t, keys, 1)
	})

	t.Run("unknown kind", func(t *testing.T) {
		b, _ := getTestBackend(t)
		require.Error(t, b.walRollback(context.Background(), &logical.Request{}, "other", nil))
	})
}

func TestSameRobotAccount(t *testing.T) {
	require.True(t, sameRobotAccount("robot$vault.ci.1", "vault.ci.1", "", ""))
	require.True(t, sameRobotAccount("robot$library+vault.ci.1", "vault.ci.1", "", ""))
	require.True(t, sameRobotAccount("bot-library+vault.ci.1", "vault.ci.1", "", ""))
	require.True(t, sameRobotAccount("vault.ci.1", "vault.ci.1", "", ""))

	// A robot_name_prefix Harbor separates with neither "$" nor "+" is recognized once recorded.
	require.False(t, sameRobotAccount("bot-vault.ci.1", "vault.ci.1", "", ""))
	require.True(t, sameRobotAccount("bot-vault.ci.1", "vault.ci.1", "bot-", ""))
	require.True(t, sameRobotAccount("bot-library+vault.ci.1", "vault.ci.1", "bot-", "library"))
	require.False(t, sameRobotAccount("robot_attacker-owned-vault.ci.1", "vault.ci.1", "robot_", ""))
	require.False(t, sameRobotAccount("bot-vault.ci.10", "vault.ci.1", "bot-", ""))
	require.False(t, sameRobotAccount("other-vault.ci.1", "vault.ci.1", "bot-", ""))

	require.False(t, sameRobotAccount("robot$attacker-owned-vault.ci.1", "vault.ci.1", "robot$", ""))
	require.False(t, sameRobotAccount("robot$vault.ci.10", "vault.ci.1", "robot$", ""))
	require.False(t, sameRobotAccount("robot$d", "vault-prod", "robot$", ""))
	require.False(t, sameRobotAccount("robot$vault.ci.1", "", "robot$", ""))
	require.False(t, sameRobotAccount("", "", "", ""))
}

// TestRevokeLogging covers the branches an operator has to tell apart after a lease is gone.
func TestRevokeLogging(t *testing.T) {
	f := newFakeHarbor(t)
	b, s, logs := getTestBackendWithLogs(t)
	configureBackend(t, b, s, f)
	resp, err := roleRequest(t, b, s, "ci", map[string]interface{}{"permissions": testProjectPermissions})
	requireNoError(t, resp, err)

	resp, err = readCreds(t, b, s, "ci")
	requireNoError(t, resp, err)
	id := resp.Data["robot_account_id"].(int64)
	name := resp.Data["robot_account_name"].(string)
	secret := roundTripSecret(t, resp.Secret)

	revoke := &logical.Request{Operation: logical.RevokeOperation, Storage: s, Secret: secret}
	resp, err = b.HandleRequest(context.Background(), revoke)
	requireNoError(t, resp, err)
	require.Contains(t, logs.String(), "revoked a Harbor robot account")
	require.Contains(t, logs.String(), fmt.Sprintf("id=%d", id))
	require.Contains(t, logs.String(), name)

	resp, err = b.HandleRequest(context.Background(), revoke)
	requireNoError(t, resp, err)
	require.Contains(t, logs.String(), "already gone from Harbor")

	delete(secret.InternalData, "robot_account_name")
	_, err = b.HandleRequest(context.Background(), revoke)
	require.Error(t, err)
	require.Contains(t, logs.String(), "cannot revoke a robot account from this lease")
	require.Contains(t, logs.String(), "key=robot_account_name")

	requireNoLoggedSecrets(t, logs, f)
}

// requireNoLoggedSecrets fails when the log output carries a credential or a WAL nonce.
func requireNoLoggedSecrets(t *testing.T, logs *logRecorder, f *fakeHarbor) {
	t.Helper()
	out := logs.String()
	require.NotEmpty(t, out)
	for _, secret := range []string{fakeHarborPassword, fakeRobotSecret} {
		require.NotContains(t, out, secret)
	}
	if create := f.lastCreate(); create != nil {
		nonce := regexp.MustCompile(`\(([0-9a-f]{32})\)$`).FindStringSubmatch(create.Description)
		require.Len(t, nonce, 2)
		require.NotContains(t, out, nonce[1])
	}
}

func TestUnprefixedRobotName(t *testing.T) {
	require.Equal(t, "vault.ci.1", unprefixedRobotName("robot$vault.ci.1"))
	require.Equal(t, "vault.ci.1", unprefixedRobotName("robot$library+vault.ci.1"))
	require.Equal(t, "vault.ci.1", unprefixedRobotName("bot-library+vault.ci.1"))
	require.Equal(t, "vault.ci.1", unprefixedRobotName("vault.ci.1"))
}
