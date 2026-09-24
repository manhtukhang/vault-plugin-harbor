package harbor

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"

	harborModel "github.com/mittwald/goharbor-client/v5/apiv2/model"
)

func readCreds(t *testing.T, b *harborBackend, s logical.Storage, role string) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation:   logical.ReadOperation,
		Path:        "creds/" + role,
		Storage:     s,
		DisplayName: "token-Some.User@Example.COM",
	})
}

func setupCredsBackend(t *testing.T, maxLeaseTTL time.Duration, permissions string, roleData map[string]interface{}) (*harborBackend, logical.Storage, *fakeHarbor) {
	t.Helper()
	f := newFakeHarbor(t)
	b, s := getTestBackendWithMaxLeaseTTL(t, maxLeaseTTL)
	configureBackend(t, b, s, f)

	// The role field is bounded by the mount ceiling of the same name.
	if allowAllProjects, _ := roleData["allow_all_projects"].(bool); allowAllProjects {
		resp, err := configRequest(t, b, s, map[string]interface{}{"allow_all_projects": true})
		requireNoError(t, resp, err)
	}

	data := map[string]interface{}{"permissions": permissions}
	for k, v := range roleData {
		data[k] = v
	}
	resp, err := roleRequest(t, b, s, "ci", data)
	requireNoError(t, resp, err)
	return b, s, f
}

func requireNoWAL(t *testing.T, s logical.Storage) {
	t.Helper()
	keys, err := framework.ListWAL(context.Background(), s)
	require.NoError(t, err)
	require.Empty(t, keys)
}

func TestCredsLifecycle(t *testing.T) {
	b, s, f := setupCredsBackend(t, 48*time.Hour, testProjectPermissions, map[string]interface{}{"ttl": "1h", "max_ttl": "10h"})
	ctx := context.Background()

	resp, err := readCreds(t, b, s, "ci")
	requireNoError(t, resp, err)
	requireNoWAL(t, s)

	id := resp.Data["robot_account_id"].(int64)
	name := resp.Data["robot_account_name"].(string)
	require.Positive(t, id)
	require.Regexp(t, `^robot\$library\+vault\.ci\.token-some\.user-example\.com\.\d{19}$`, name)
	require.Equal(t, fakeRobotSecret, resp.Data["robot_account_secret"])
	token, err := base64.StdEncoding.DecodeString(resp.Data["robot_account_auth_token"].(string))
	require.NoError(t, err)
	require.Equal(t, name+":"+fakeRobotSecret, string(token))

	create := f.lastCreate()
	require.Equal(t, robotKindProject, create.Level)
	require.Equal(t, int64(1), create.Duration)
	require.Regexp(t, harborRobotNameRegexp, create.Name)

	require.Equal(t, time.Hour, resp.Secret.TTL)
	require.Equal(t, 10*time.Hour, resp.Secret.MaxTTL)
	require.Regexp(t, `\([0-9a-f]{32}\)$`, create.Description)
	require.Equal(t, map[string]interface{}{
		"secret_type":        harborRobotAccountType,
		"role":               "ci",
		"robot_account_id":   id,
		"robot_account_name": name,
		"robot_name":         create.Name,
		"harbor_url":         f.URL(),
		"max_ttl":            int64(36000),
	}, resp.Secret.InternalData)

	revoke := &logical.Request{Operation: logical.RevokeOperation, Storage: s, Secret: resp.Secret}
	resp, err = b.HandleRequest(ctx, revoke)
	requireNoError(t, resp, err)
	_, found := f.robot(id)
	require.False(t, found)
	require.Equal(t, []int64{id}, f.deletedIDs())

	resp, err = b.HandleRequest(ctx, revoke)
	requireNoError(t, resp, err)
	require.Equal(t, []int64{id}, f.deletedIDs())
}

func TestCredsSystemLevel(t *testing.T) {
	b, s, f := setupCredsBackend(t, 48*time.Hour, testSystemPermissions, map[string]interface{}{"allow_all_projects": true})

	resp, err := readCreds(t, b, s, "ci")
	requireNoError(t, resp, err)
	require.Equal(t, robotKindSystem, f.lastCreate().Level)
	require.Regexp(t, `^robot\$vault\.ci\.`, resp.Data["robot_account_name"])
	require.Equal(t, "", f.lastCreate().Permissions[0].Access[0].Effect)
}

func TestCredsAddsPullToPush(t *testing.T) {
	cases := map[string]struct {
		permissions string
		roleData    map[string]interface{}
		level       string
	}{
		"project": {
			`[{"kind":"project","namespace":"library","access":[{"resource":"repository","action":"push"}]}]`,
			nil,
			robotKindProject,
		},
		"all projects": {
			`[{"kind":"project","namespace":"*","access":[{"resource":"repository","action":"push"}]}]`,
			map[string]interface{}{"allow_all_projects": true},
			robotKindSystem,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			b, s, f := setupCredsBackend(t, 48*time.Hour, tc.permissions, tc.roleData)

			resp, err := readCreds(t, b, s, "ci")
			requireNoError(t, resp, err)

			create := f.lastCreate()
			require.Equal(t, tc.level, create.Level)
			require.Equal(t, []*harborModel.Access{
				{Resource: "repository", Action: "push"},
				{Resource: "repository", Action: "pull"},
			}, create.Permissions[0].Access, "Harbor derives the pull from the push for project level robots only")
			require.JSONEq(t, tc.permissions, readRole(t, b, s, "ci").Data["permissions"].(string))
		})
	}
}

// TestCredsRevalidatesStoredRole covers a role written by a version whose allowlist was wider.
func TestCredsRevalidatesStoredRole(t *testing.T) {
	cases := map[string]*harborRoleEntry{
		"system kind": {Permissions: []*harborModel.RobotPermission{{
			Kind:      robotKindSystem,
			Namespace: "/",
			Access:    []*harborModel.Access{{Resource: "catalog", Action: "read"}},
		}}},
		"all projects": {Permissions: []*harborModel.RobotPermission{{
			Kind:      robotKindProject,
			Namespace: "*",
			Access:    []*harborModel.Access{{Resource: "repository", Action: "pull"}},
		}}},
		"no permission": {},
	}

	for name, role := range cases {
		t.Run(name, func(t *testing.T) {
			b, s, f := setupCredsBackend(t, 48*time.Hour, testProjectPermissions, nil)
			require.NoError(t, setRole(context.Background(), s, "ci", role))
			requests := len(f.requestLog())

			resp, err := readCreds(t, b, s, "ci")
			requireErrorResponse(t, resp, err, "not allowed")
			require.Zero(t, f.robotCount())
			require.Len(t, f.requestLog(), requests, "no Harbor call is made")
			requireNoWAL(t, s)
		})
	}
}

func TestCredsOperations(t *testing.T) {
	b, s, _ := setupCredsBackend(t, 48*time.Hour, testProjectPermissions, nil)
	ctx := context.Background()

	for _, op := range []logical.Operation{logical.UpdateOperation, logical.CreateOperation, logical.DeleteOperation} {
		_, err := b.HandleRequest(ctx, &logical.Request{Operation: op, Path: "creds/ci", Storage: s})
		require.ErrorIs(t, err, logical.ErrUnsupportedOperation, op)
	}

	resp, err := readCreds(t, b, s, "missing")
	requireErrorResponse(t, resp, err, "unknown role")

	props := pathCreds(b).Operations[logical.ReadOperation].Properties()
	require.True(t, props.ForwardPerformanceStandby)
	require.True(t, props.ForwardPerformanceSecondary)
}

func TestCredsNotConfigured(t *testing.T) {
	b, s := getTestBackend(t)
	resp, err := roleRequest(t, b, s, "ci", map[string]interface{}{"permissions": testProjectPermissions})
	requireNoError(t, resp, err)

	_, err = readCreds(t, b, s, "ci")
	require.ErrorIs(t, err, errBackendNotConfigured)
}

func TestCredsDuration(t *testing.T) {
	cases := []struct {
		name          string
		systemMaxTTL  time.Duration
		roleMaxTTL    time.Duration
		expectedMax   time.Duration
		expectedDays  int64
		bypassRoleAPI bool
	}{
		{"system default", 48 * time.Hour, 0, 48 * time.Hour, 3, false},
		{"one hour", 48 * time.Hour, time.Hour, time.Hour, 1, false},
		{"one day minus margin", 48 * time.Hour, 23 * time.Hour, 23 * time.Hour, 1, false},
		{"exactly one day", 48 * time.Hour, 24 * time.Hour, 24 * time.Hour, 2, false},
		{"just over one day", 48 * time.Hour, 25 * time.Hour, 25 * time.Hour, 2, false},
		{"short system max", 30 * time.Second, 0, 30 * time.Second, 1, false},
		{"role above tuned mount max", 48 * time.Hour, 72 * time.Hour, 48 * time.Hour, 3, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, s, f := setupCredsBackend(t, tc.systemMaxTTL, testProjectPermissions, nil)
			if tc.roleMaxTTL > 0 {
				role, err := b.getRole(context.Background(), s, "ci")
				require.NoError(t, err)
				role.MaxTTL = tc.roleMaxTTL
				if tc.bypassRoleAPI {
					require.NoError(t, setRole(context.Background(), s, "ci", role))
				} else {
					resp, err := roleRequest(t, b, s, "ci", map[string]interface{}{"max_ttl": int(tc.roleMaxTTL.Seconds())})
					requireNoError(t, resp, err)
				}
			}

			resp, err := readCreds(t, b, s, "ci")
			requireNoError(t, resp, err)
			require.Equal(t, tc.expectedMax, resp.Secret.MaxTTL)
			require.Equal(t, int64(tc.expectedMax/time.Second), resp.Secret.InternalData["max_ttl"])
			require.Equal(t, tc.expectedDays, f.lastCreate().Duration)
		})
	}
}

func TestHarborDurationDays(t *testing.T) {
	cases := map[time.Duration]int64{
		0:                           1,
		time.Second:                 1,
		23 * time.Hour:              1,
		23*time.Hour + time.Second:  2,
		24 * time.Hour:              2,
		47 * time.Hour:              2,
		48 * time.Hour:              3,
		30 * 24 * time.Hour:         31,
		30*24*time.Hour - time.Hour: 30,
	}
	for in, expected := range cases {
		require.Equal(t, expected, harborDurationDays(in), in.String())
	}
}

func TestCredsInvalidCreateResponses(t *testing.T) {
	t.Run("empty body", func(t *testing.T) {
		b, s, f := setupCredsBackend(t, 48*time.Hour, testProjectPermissions, nil)
		f.onCreate = func(w http.ResponseWriter, _ *harborModel.RobotCreate) bool {
			w.WriteHeader(http.StatusCreated)
			return true
		}
		_, err := readCreds(t, b, s, "ci")
		require.ErrorContains(t, err, "invalid response")
		keys, err := framework.ListWAL(context.Background(), s)
		require.NoError(t, err)
		require.Len(t, keys, 1, "an unknown outcome must leave the WAL entry for rollback")
	})

	t.Run("missing secret", func(t *testing.T) {
		b, s, f := setupCredsBackend(t, 48*time.Hour, testProjectPermissions, nil)
		f.onCreate = func(w http.ResponseWriter, create *harborModel.RobotCreate) bool {
			id := f.nextID
			f.nextID++
			f.robots[id] = &fakeRobot{Robot: harborModel.Robot{ID: id, Level: create.Level}, stored: create.Name}
			writeJSON(w, http.StatusCreated, &harborModel.RobotCreated{ID: id, Name: "robot$" + create.Name})
			return true
		}
		_, err := readCreds(t, b, s, "ci")
		require.ErrorContains(t, err, "invalid response")
		require.Zero(t, f.robotCount())
		requireNoWAL(t, s)
	})

	t.Run("rejected by harbor", func(t *testing.T) {
		b, s, f := setupCredsBackend(t, 48*time.Hour, `[{"kind":"project","namespace":"missing","access":[{"resource":"repository","action":"pull"}]}]`, nil)
		_, err := readCreds(t, b, s, "ci")
		require.ErrorContains(t, err, "HTTP 404")
		require.Zero(t, f.robotCount())

		keys, err := framework.ListWAL(context.Background(), s)
		require.NoError(t, err)
		require.Len(t, keys, 1, "a 4xx never proves that Harbor created nothing")

		resp, err := rollback(t, b, s)
		requireNoError(t, resp, err)
		requireNoWAL(t, s)
		require.Zero(t, f.robotCount())
	})

	// An intermediary can answer 4xx for a create Harbor committed.
	for _, status := range []int{http.StatusTooManyRequests, http.StatusRequestTimeout} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			b, s, f := setupCredsBackend(t, 48*time.Hour, testProjectPermissions, nil)
			f.onCreate = func(w http.ResponseWriter, create *harborModel.RobotCreate) bool {
				f.robots[f.nextID] = &fakeRobot{
					Robot:     harborModel.Robot{ID: f.nextID, Level: create.Level, Description: create.Description},
					stored:    "library+" + create.Name,
					projectID: 1,
				}
				f.nextID++
				writeHarborError(w, status, http.StatusText(status))
				return true
			}

			_, err := readCreds(t, b, s, "ci")
			require.ErrorContains(t, err, fmt.Sprintf("HTTP %d", status))
			require.Equal(t, 1, f.robotCount())
			keys, err := framework.ListWAL(context.Background(), s)
			require.NoError(t, err)
			require.Len(t, keys, 1)

			resp, err := rollback(t, b, s)
			requireNoError(t, resp, err)
			requireNoWAL(t, s)
			require.Zero(t, f.robotCount(), "the orphaned robot account must be deleted")
		})
	}

	t.Run("server error", func(t *testing.T) {
		b, s, f := setupCredsBackend(t, 48*time.Hour, testProjectPermissions, nil)
		f.onCreate = func(w http.ResponseWriter, _ *harborModel.RobotCreate) bool {
			writeHarborError(w, http.StatusInternalServerError, "boom")
			return true
		}
		_, err := readCreds(t, b, s, "ci")
		require.ErrorContains(t, err, "HTTP 500")
		keys, err := framework.ListWAL(context.Background(), s)
		require.NoError(t, err)
		require.Len(t, keys, 1)
	})
}

func TestCredsIgnoreDebugEnv(t *testing.T) {
	t.Setenv("DEBUG", "1")
	t.Setenv("SWAGGER_DEBUG", "1")
	b, s, _ := setupCredsBackend(t, 48*time.Hour, testProjectPermissions, nil)

	r, w, err := os.Pipe()
	require.NoError(t, err)
	stdout, stderr := os.Stdout, os.Stderr
	os.Stdout, os.Stderr = w, w
	output := make(chan string)
	go func() {
		data, _ := io.ReadAll(r)
		output <- string(data)
	}()

	resp, reqErr := readCreds(t, b, s, "ci")

	os.Stdout, os.Stderr = stdout, stderr
	require.NoError(t, w.Close())
	captured := <-output

	requireNoError(t, resp, reqErr)
	require.NotContains(t, captured, fakeHarborPassword)
	require.NotContains(t, captured, fakeRobotSecret)
	require.NotContains(t, captured, "Authorization")
}

func TestRobotAccountName(t *testing.T) {
	now := time.Unix(0, 1700000000123456789)
	const ts = ".1700000000123456789"

	cases := []struct {
		role, displayName, expected string
	}{
		{"ci", "", "vault.ci" + ts},
		{"ci", "token", "vault.ci.token" + ts},
		{"ci", "OIDC-John.Doe@Example.COM", "vault.ci.oidc-john.doe-example.com" + ts},
		{"ci", "--a..b__c--", "vault.ci.a.b_c" + ts},
		{"ci", "a .-_b", "vault.ci.a-b" + ts},
		{"ci", "日本語", "vault.ci" + ts},
		{"ci", "@@@", "vault.ci" + ts},
		{"ci", strings.Repeat("a", 40), "vault.ci." + strings.Repeat("a", 32) + ts},
		{"ci", strings.Repeat("a", 31) + ".b", "vault.ci." + strings.Repeat("a", 31) + ts},
		{strings.Repeat("r", 200), "token", "vault." + strings.Repeat("r", 102) + ts},
		{strings.Repeat("r", 101) + ".x", "", "vault." + strings.Repeat("r", 101) + ts},
	}

	for _, tc := range cases {
		got := robotAccountName(tc.role, tc.displayName, robotNameMaxLen, now)
		require.Equal(t, tc.expected, got, "role=%q display=%q", tc.role, tc.displayName)
		require.Regexp(t, harborRobotNameRegexp, got)
		require.LessOrEqual(t, len(got), robotNameMaxLen)
	}

	got := robotAccountName("ci", "token-some.user", 34, now)
	require.Equal(t, "vault.ci.token"+ts, got)
}

func TestCredsLongProjectName(t *testing.T) {
	project := strings.Repeat("p", 220)
	perms := fmt.Sprintf(`[{"kind":"project","namespace":%q,"access":[{"resource":"repository","action":"pull"}]}]`, project)
	b, s, f := setupCredsBackend(t, 48*time.Hour, perms, nil)
	f.addProject(project, 2)

	resp, err := readCreds(t, b, s, "ci")
	requireNoError(t, resp, err)
	create := f.lastCreate()
	require.Regexp(t, harborRobotNameRegexp, create.Name)
	require.LessOrEqual(t, len(project)+1+len(create.Name), harborNameMaxLen)
	require.Equal(t, "robot$"+project+"+"+create.Name, resp.Data["robot_account_name"])

	tooLong := strings.Repeat("q", 240)
	roleResp, err := roleRequest(t, b, s, "long", map[string]interface{}{
		"permissions": fmt.Sprintf(`[{"kind":"project","namespace":%q,"access":[{"resource":"repository","action":"pull"}]}]`, tooLong),
	})
	requireNoError(t, roleResp, err)
	resp, err = readCreds(t, b, s, "long")
	requireErrorResponse(t, resp, err, "too long")
	requireNoWAL(t, s)
}

func TestCredsCustomRobotPrefix(t *testing.T) {
	ctx := context.Background()
	for _, prefix := range []string{"robot$", "robot_", "bot-"} {
		for _, perms := range []string{testProjectPermissions, testSystemPermissions} {
			level := robotLevel(mustParsePermissions(t, perms, true))
			t.Run(prefix+" "+level, func(t *testing.T) {
				b, s, f := setupCredsBackend(t, 48*time.Hour, perms, map[string]interface{}{"allow_all_projects": true})
				f.setPrefix(prefix)
				// Harbor separates a project robot's name from its robot_name_prefix with "+"; a
				// system robot's name is not, so a prefix without "$" has to have been recorded.
				if level == robotKindSystem && prefix != "robot$" {
					setRobotPrefix(t, s, prefix)
				}

				resp, err := readCreds(t, b, s, "ci")
				requireNoError(t, resp, err)
				require.True(t, strings.HasPrefix(resp.Data["robot_account_name"].(string), prefix))
				id := resp.Data["robot_account_id"].(int64)

				resp, err = b.HandleRequest(ctx, &logical.Request{Operation: logical.RevokeOperation, Storage: s, Secret: roundTripSecret(t, resp.Secret)})
				requireNoError(t, resp, err)
				require.Equal(t, []int64{id}, f.deletedIDs())
			})
		}
	}

	t.Run("prefix changed after issuance", func(t *testing.T) {
		for _, keepRobotName := range []bool{true, false} {
			b, s, f := setupCredsBackend(t, 48*time.Hour, testProjectPermissions, nil)
			resp, err := readCreds(t, b, s, "ci")
			requireNoError(t, resp, err)
			id := resp.Data["robot_account_id"].(int64)
			secret := roundTripSecret(t, resp.Secret)
			if !keepRobotName {
				delete(secret.InternalData, "robot_name")
			}

			f.setPrefix("bot-")
			resp, err = b.HandleRequest(ctx, &logical.Request{Operation: logical.RevokeOperation, Storage: s, Secret: secret})
			requireNoError(t, resp, err)
			require.Equal(t, []int64{id}, f.deletedIDs())
		}
	})
}

// TestCredsRefusesForeignRobotAccount covers a create answered with a valid id and secret but the
// name of another robot account: its credentials could be revoked by neither the lease nor the WAL.
func TestCredsRefusesForeignRobotAccount(t *testing.T) {
	for name, returned := range map[string]func(requested string) string{
		"other name":    func(string) string { return "robot$library+someone-else" },
		"name extended": func(requested string) string { return "robot$library+attacker-owned-" + requested },
	} {
		t.Run(name, func(t *testing.T) {
			b, s, f := setupCredsBackend(t, 48*time.Hour, testProjectPermissions, nil)
			f.onCreate = func(w http.ResponseWriter, create *harborModel.RobotCreate) bool {
				id := f.nextID
				f.nextID++
				f.robots[id] = &fakeRobot{
					Robot:     harborModel.Robot{ID: id, Level: create.Level, Description: create.Description},
					stored:    "library+" + create.Name,
					projectID: 1,
					secret:    fakeRobotSecret,
				}
				writeJSON(w, http.StatusCreated, &harborModel.RobotCreated{ID: id, Name: returned(create.Name), Secret: fakeRobotSecret})
				return true
			}

			_, err := readCreds(t, b, s, "ci")
			require.ErrorContains(t, err, "instead of")
			require.ErrorContains(t, err, returned(f.lastCreate().Name))
			require.NotContains(t, err.Error(), fakeRobotSecret)
			require.Equal(t, 1, f.robotCount())

			keys, err := framework.ListWAL(context.Background(), s)
			require.NoError(t, err)
			require.Len(t, keys, 1, "the WAL entry reclaims the robot account whatever Harbor answered")

			f.onCreate = nil
			resp, err := rollback(t, b, s)
			requireNoError(t, resp, err)
			requireNoWAL(t, s)
			require.Zero(t, f.robotCount())
		})
	}
}

// TestCredsUnrecognizedRobotPrefix covers a robot_name_prefix the backend has not recorded: a
// system robot's name is not separated from it, so it cannot be told apart from the name itself.
func TestCredsUnrecognizedRobotPrefix(t *testing.T) {
	b, s, f := setupCredsBackend(t, 48*time.Hour, testSystemPermissions, map[string]interface{}{"allow_all_projects": true})
	f.setPrefix("bot-")

	_, err := readCreds(t, b, s, "ci")
	require.ErrorContains(t, err, "instead of")
	require.Equal(t, 1, f.robotCount(), "the robot account Harbor created is left for an operator to delete")
}

func TestCredsLogsIssuance(t *testing.T) {
	f := newFakeHarbor(t)
	b, s, logs := getTestBackendWithLogs(t)
	configureBackend(t, b, s, f)
	resp, err := roleRequest(t, b, s, "ci", map[string]interface{}{"permissions": testProjectPermissions, "max_ttl": "10h"})
	requireNoError(t, resp, err)

	resp, err = readCreds(t, b, s, "ci")
	requireNoError(t, resp, err)

	out := logs.String()
	require.Contains(t, out, "issued a Harbor robot account")
	require.Contains(t, out, "role=ci")
	require.Contains(t, out, fmt.Sprintf("id=%d", resp.Data["robot_account_id"]))
	require.Contains(t, out, resp.Data["robot_account_name"].(string))
	require.Contains(t, out, "level="+robotKindProject)
	require.Contains(t, out, "project=library")
	require.Contains(t, out, f.URL())
	require.Contains(t, out, "max_ttl=10h0m0s")
	require.NotContains(t, out, resp.Data["robot_account_auth_token"].(string))
	requireNoLoggedSecrets(t, logs, f)
}

func mustParsePermissions(t *testing.T, raw string, allowAllProjects bool) []*harborModel.RobotPermission {
	t.Helper()
	perms, err := parsePermissions(raw, allowAllProjects)
	require.NoError(t, err)
	return perms
}
