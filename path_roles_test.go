package harbor

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"

	harborModel "github.com/mittwald/goharbor-client/v5/apiv2/model"
)

const (
	testProjectPermissions = `[{"kind":"project","namespace":"library","access":[{"resource":"repository","action":"pull"}]}]`
	testSystemPermissions  = `[
		{"kind":"project","namespace":"*","access":[{"resource":"repository","action":"pull","effect":"allow"}]}
	]`
)

func roleRequest(t *testing.T, b *harborBackend, s logical.Storage, name string, data map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	return handleWrite(t, b, &logical.Request{Path: "roles/" + name, Storage: s, Data: data})
}

func readRole(t *testing.T, b *harborBackend, s logical.Storage, name string) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/" + name,
		Storage:   s,
	})
	require.NoError(t, err)
	return resp
}

func TestParsePermissions(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		perms, err := parsePermissions(testSystemPermissions, true)
		require.NoError(t, err)
		require.Len(t, perms, 1)
		require.Equal(t, "", perms[0].Access[0].Effect, "allow must be normalized to Harbor's empty effect")

		perms, err = parsePermissions(` [{"kind":"project","namespace":"library","access":[{"resource":"repository","action":"push"}]}] `, false)
		require.NoError(t, err)
		require.Equal(t, actionPush, perms[0].Access[0].Action)
	})

	t.Run("allowlist", func(t *testing.T) {
		for kind, resources := range allowedAccess {
			namespace := "library"
			if kind == robotKindSystem {
				namespace = "/"
			}
			for resource, actions := range resources {
				for action := range actions {
					_, err := parsePermissions(fmt.Sprintf(`[{"kind":%q,"namespace":%q,"access":[{"resource":%q,"action":%q}]}]`, kind, namespace, resource, action), false)
					require.NoError(t, err, "%s %s:%s", kind, resource, action)
				}
			}
		}
	})

	t.Run("project namespaces", func(t *testing.T) {
		for _, ns := range []string{"library", "a.b-c_d", strings.Repeat("a", 255)} {
			_, err := parsePermissions(fmt.Sprintf(`[{"kind":"project","namespace":%q,"access":[{"resource":"repository","action":"pull"}]}]`, ns), false)
			require.NoError(t, err, ns)
		}
	})

	t.Run("all projects", func(t *testing.T) {
		_, err := parsePermissions(testSystemPermissions, false)
		require.ErrorContains(t, err, "allow_all_projects")

		_, err = parsePermissions(testSystemPermissions, true)
		require.NoError(t, err)
	})

	invalid := map[string]string{
		"empty string":       ``,
		"not json":           `nope`,
		"empty list":         `[]`,
		"null":               `null`,
		"null permission":    `[null]`,
		"object":             `{"kind":"project"}`,
		"trailing value":     testProjectPermissions + ` []`,
		"unknown field":      `[{"kind":"project","namespace":"library","scope":"x","access":[{"resource":"repository","action":"pull"}]}]`,
		"unknown access key": `[{"kind":"project","namespace":"library","access":[{"resource":"repository","action":"pull","extra":1}]}]`,
		"bad kind":           `[{"kind":"global","namespace":"/","access":[{"resource":"repository","action":"pull"}]}]`,
		"system namespace":   `[{"kind":"system","namespace":"library","access":[{"resource":"project","action":"list"}]}]`,
		"project namespace":  `[{"kind":"project","namespace":"","access":[{"resource":"repository","action":"pull"}]}]`,
		"empty access":       `[{"kind":"project","namespace":"library","access":[]}]`,
		"null access":        `[{"kind":"project","namespace":"library","access":[null]}]`,
		"wildcard resource":  `[{"kind":"project","namespace":"library","access":[{"resource":"*","action":"pull"}]}]`,
		"wildcard action":    `[{"kind":"project","namespace":"library","access":[{"resource":"repository","action":"*"}]}]`,
		"empty resource":     `[{"kind":"project","namespace":"library","access":[{"action":"pull"}]}]`,
		"empty action":       `[{"kind":"project","namespace":"library","access":[{"resource":"repository"}]}]`,
		"bad effect":         `[{"kind":"project","namespace":"library","access":[{"resource":"repository","action":"pull","effect":"maybe"}]}]`,
		"deny effect":        `[{"kind":"project","namespace":"library","access":[{"resource":"repository","action":"push","effect":"deny"}]}]`,
		"project on system":  `[{"kind":"system","namespace":"/","access":[{"resource":"repository","action":"pull"}]}]`,
		"system catalog":     `[{"kind":"system","namespace":"/","access":[{"resource":"catalog","action":"read"}]}]`,
		"system project":     `[{"kind":"system","namespace":"/","access":[{"resource":"project","action":"list"}]}]`,
	}
	for _, ns := range []string{"Library", "a..b", "-a", "a b", "a+b", strings.Repeat("a", 256)} {
		invalid["namespace "+ns] = fmt.Sprintf(`[{"kind":"project","namespace":%q,"access":[{"resource":"repository","action":"pull"}]}]`, ns)
	}
	denied := map[string][][2]string{
		robotKindProject: {
			{"robot", "create"}, {"member", "create"}, {"scanner", "create"}, {"project", "update"}, {"project", "delete"},
			{"metadata", "update"}, {"metadata", "create"}, {"preheat-policy", "create"}, {"notification-policy", "create"},
			{"tag-retention", "update"}, {"immutable-tag", "create"}, {"repository", "update"}, {"artifact", "create"},
			{"label", "create"}, {"export-cve", "create"}, {"configuration", "update"},
		},
		robotKindSystem: {
			{"robot", "create"}, {"user", "create"}, {"user-group", "create"}, {"ldap-user", "create"}, {"registry", "create"},
			{"replication-policy", "create"}, {"replication", "create"}, {"preheat-instance", "create"}, {"purge-audit", "create"},
			{"garbage-collection", "create"}, {"scanner", "create"}, {"scan-all", "create"}, {"project", "create"},
			{"quota", "update"}, {"audit-log", "list"}, {"label", "create"},
		},
	}
	for kind, pairs := range denied {
		namespace := "*"
		if kind == robotKindSystem {
			namespace = "/"
		}
		for _, pair := range pairs {
			invalid[fmt.Sprintf("denied %s %s:%s", kind, pair[0], pair[1])] = fmt.Sprintf(`[{"kind":%q,"namespace":%q,"access":[{"resource":%q,"action":%q}]}]`, kind, namespace, pair[0], pair[1])
		}
	}

	for name, raw := range invalid {
		t.Run(name, func(t *testing.T) {
			_, err := parsePermissions(raw, true)
			require.Error(t, err)
		})
	}
}

func TestWithImplicitPull(t *testing.T) {
	pull := &harborModel.Access{Resource: resourceRepository, Action: actionPull}
	push := &harborModel.Access{Resource: resourceRepository, Action: actionPush}
	list := &harborModel.Access{Resource: resourceRepository, Action: "list"}

	cases := []struct {
		access   []*harborModel.Access
		expected []*harborModel.Access
	}{
		{[]*harborModel.Access{push}, []*harborModel.Access{push, pull}},
		{[]*harborModel.Access{list, push}, []*harborModel.Access{list, push, pull}},
		{[]*harborModel.Access{pull, push}, []*harborModel.Access{pull, push}},
		{[]*harborModel.Access{pull}, []*harborModel.Access{pull}},
		{[]*harborModel.Access{list}, []*harborModel.Access{list}},
	}

	for i, tc := range cases {
		permissions := []*harborModel.RobotPermission{{Kind: robotKindProject, Namespace: "library", Access: tc.access}}
		got := withImplicitPull(permissions)
		require.Len(t, got, 1, "case %d", i)
		require.Equal(t, tc.expected, got[0].Access, "case %d", i)
		require.Equal(t, tc.access, permissions[0].Access, "case %d: the stored role must not change", i)
	}
}

func TestRoleSystemKind(t *testing.T) {
	require.Empty(t, allowedAccess[robotKindSystem], "no system scope access may be delegated")

	b, s := getTestBackend(t)
	for _, access := range []string{`{"resource":"catalog","action":"read"}`, `{"resource":"project","action":"list"}`} {
		resp, err := roleRequest(t, b, s, "sys", map[string]interface{}{
			"permissions": fmt.Sprintf(`[{"kind":"system","namespace":"/","access":[%s]}]`, access),
		})
		requireErrorResponse(t, resp, err, "kind system is not supported")
		require.Nil(t, readRole(t, b, s, "sys"))
	}
}

// configureMountAllowAllProjects writes the backend configuration, whose allow_all_projects is the
// ceiling for the role field of the same name.
func configureMountAllowAllProjects(t *testing.T, b *harborBackend, s logical.Storage, f *fakeHarbor, allow bool) {
	t.Helper()
	resp, err := configRequest(t, b, s, map[string]interface{}{
		"url":                f.URL(),
		"username":           fakeHarborUsername,
		"password":           fakeHarborPassword,
		"ca_cert":            f.CACert(),
		"allow_all_projects": allow,
	})
	requireNoError(t, resp, err)
}

func TestRoleAllowAllProjects(t *testing.T) {
	f := newFakeHarbor(t)
	b, s := getTestBackend(t)

	allRole := map[string]interface{}{
		"permissions":        testSystemPermissions,
		"allow_all_projects": true,
	}

	resp, err := roleRequest(t, b, s, "all", allRole)
	requireErrorResponse(t, resp, err, "backend configuration")
	require.Nil(t, readRole(t, b, s, "all"))

	configureMountAllowAllProjects(t, b, s, f, false)
	resp, err = roleRequest(t, b, s, "all", allRole)
	requireErrorResponse(t, resp, err, "backend configuration")
	require.Nil(t, readRole(t, b, s, "all"))

	configureMountAllowAllProjects(t, b, s, f, true)
	resp, err = roleRequest(t, b, s, "all", map[string]interface{}{"permissions": testSystemPermissions})
	requireErrorResponse(t, resp, err, "allow_all_projects")
	require.Nil(t, readRole(t, b, s, "all"))

	resp, err = roleRequest(t, b, s, "all", allRole)
	requireNoError(t, resp, err)
	require.Equal(t, true, readRole(t, b, s, "all").Data["allow_all_projects"])

	resp, err = roleRequest(t, b, s, "all", map[string]interface{}{"allow_all_projects": false})
	requireErrorResponse(t, resp, err, "allow_all_projects")
	require.Equal(t, true, readRole(t, b, s, "all").Data["allow_all_projects"], "the role keeps its stored flag")

	configureMountAllowAllProjects(t, b, s, f, false)
	require.Equal(t, false, readRole(t, b, s, "all").Data["allow_all_projects"], "the mount ceiling disarms the stored flag")

	resp, err = roleRequest(t, b, s, "ci", map[string]interface{}{"permissions": testProjectPermissions})
	requireNoError(t, resp, err)
	require.Equal(t, false, readRole(t, b, s, "ci").Data["allow_all_projects"])
}

// TestRoleAllowAllProjectsAtIssuance checks the ceiling where the role was stored while the mount
// allowed it, which is the only path left once the role exists.
func TestRoleAllowAllProjectsAtIssuance(t *testing.T) {
	f := newFakeHarbor(t)
	b, s := getTestBackend(t)
	configureMountAllowAllProjects(t, b, s, f, true)

	resp, err := roleRequest(t, b, s, "all", map[string]interface{}{
		"permissions":        testSystemPermissions,
		"allow_all_projects": true,
	})
	requireNoError(t, resp, err)

	creds := &logical.Request{
		Operation:   logical.ReadOperation,
		Path:        "creds/all",
		Storage:     s,
		DisplayName: "token-test",
	}
	resp, err = b.HandleRequest(context.Background(), creds)
	requireNoError(t, resp, err)
	require.Equal(t, 1, f.robotCount())

	configureMountAllowAllProjects(t, b, s, f, false)

	resp, err = b.HandleRequest(context.Background(), creds)
	requireErrorResponse(t, resp, err, "allow_all_projects")
	require.Equal(t, 1, f.robotCount())
}

func TestRobotLevel(t *testing.T) {
	project := &harborModel.RobotPermission{Kind: robotKindProject, Namespace: "library"}
	allProjects := &harborModel.RobotPermission{Kind: robotKindProject, Namespace: "*"}
	system := &harborModel.RobotPermission{Kind: robotKindSystem, Namespace: "/"}

	cases := []struct {
		perms    []*harborModel.RobotPermission
		expected string
	}{
		{[]*harborModel.RobotPermission{project}, robotKindProject},
		{[]*harborModel.RobotPermission{allProjects}, robotKindSystem},
		{[]*harborModel.RobotPermission{system}, robotKindSystem},
		{[]*harborModel.RobotPermission{project, project}, robotKindSystem},
		{[]*harborModel.RobotPermission{project, system}, robotKindSystem},
	}
	for i, tc := range cases {
		require.Equal(t, tc.expected, robotLevel(tc.perms), "case %d", i)
	}
}

func TestRoleCreateAndUpdate(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()
	configureMountAllowAllProjects(t, b, s, newFakeHarbor(t), true)

	existence := func(name string) bool {
		checkFound, exists, err := b.HandleExistenceCheck(ctx, &logical.Request{
			Operation: logical.CreateOperation,
			Path:      "roles/" + name,
			Storage:   s,
		})
		require.NoError(t, err)
		require.True(t, checkFound)
		return exists
	}

	require.False(t, existence("reader"))

	resp, err := roleRequest(t, b, s, "reader", map[string]interface{}{"ttl": "1h"})
	requireErrorResponse(t, resp, err, "missing permissions")

	resp, err = roleRequest(t, b, s, "reader", map[string]interface{}{
		"permissions": testProjectPermissions,
		"ttl":         "1h",
		"max_ttl":     "10h",
	})
	requireNoError(t, resp, err)
	require.True(t, existence("reader"))

	resp, err = roleRequest(t, b, s, "reader", map[string]interface{}{"ttl": "2h"})
	requireNoError(t, resp, err)
	data := readRole(t, b, s, "reader").Data
	require.Equal(t, (2 * time.Hour).Seconds(), data["ttl"])
	require.Equal(t, (10 * time.Hour).Seconds(), data["max_ttl"])
	require.JSONEq(t, testProjectPermissions, data["permissions"].(string))

	resp, err = roleRequest(t, b, s, "reader", map[string]interface{}{
		"permissions":        testSystemPermissions,
		"allow_all_projects": true,
	})
	requireNoError(t, resp, err)
	data = readRole(t, b, s, "reader").Data
	require.Equal(t, (2 * time.Hour).Seconds(), data["ttl"])
	require.Equal(t, (10 * time.Hour).Seconds(), data["max_ttl"])
	var perms []*harborModel.RobotPermission
	require.NoError(t, json.Unmarshal([]byte(data["permissions"].(string)), &perms))
	require.Len(t, perms, 1)

	resp, err = roleRequest(t, b, s, "reader", map[string]interface{}{"permissions": `[]`})
	requireErrorResponse(t, resp, err, "invalid permissions")
	require.Len(t, perms, 1)
}

func TestRoleTTLValidation(t *testing.T) {
	b, s := getTestBackendWithMaxLeaseTTL(t, 48*time.Hour)

	resp, err := roleRequest(t, b, s, "r", map[string]interface{}{
		"permissions": testProjectPermissions,
		"max_ttl":     "49h",
	})
	requireErrorResponse(t, resp, err, "max_ttl")

	resp, err = roleRequest(t, b, s, "r", map[string]interface{}{
		"permissions": testProjectPermissions,
		"ttl":         "2h",
		"max_ttl":     "1h",
	})
	requireErrorResponse(t, resp, err, "ttl cannot be greater than max_ttl")

	resp, err = roleRequest(t, b, s, "r", map[string]interface{}{
		"permissions": testProjectPermissions,
		"ttl":         "1h",
		"max_ttl":     "48h",
	})
	requireNoError(t, resp, err)

	resp, err = roleRequest(t, b, s, "r", map[string]interface{}{"ttl": "49h"})
	requireErrorResponse(t, resp, err, "ttl cannot be greater than max_ttl")
}

func TestRoleNamePattern(t *testing.T) {
	b, s := getTestBackend(t)
	resp, err := roleRequest(t, b, s, "admin", map[string]interface{}{"permissions": testProjectPermissions})
	requireNoError(t, resp, err)

	for _, path := range []string{"roles/ADMIN", "roles/Admin", "roles/a..b", "roles/-a", "roles/a-", "roles/a_", "creds/ADMIN", "creds/Admin", "creds/a..b"} {
		for _, op := range []logical.Operation{logical.ReadOperation, logical.CreateOperation, logical.UpdateOperation, logical.DeleteOperation} {
			_, err := b.HandleRequest(context.Background(), &logical.Request{
				Operation: op,
				Path:      path,
				Storage:   s,
				Data:      map[string]interface{}{"permissions": testProjectPermissions},
			})
			require.ErrorIs(t, err, logical.ErrUnsupportedPath, "%s %s", op, path)
		}
	}

	for _, name := range []string{"a", "a.b", "a-b_c.d", "0"} {
		resp, err := roleRequest(t, b, s, name, map[string]interface{}{"permissions": testProjectPermissions})
		requireNoError(t, resp, err)
	}
}

func TestRoleListReadDelete(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()

	for i := 1; i <= 10; i++ {
		resp, err := roleRequest(t, b, s, "role"+strconv.Itoa(i), map[string]interface{}{"permissions": testProjectPermissions})
		requireNoError(t, resp, err)
	}

	resp, err := b.HandleRequest(ctx, &logical.Request{Operation: logical.ListOperation, Path: "roles/", Storage: s})
	requireNoError(t, resp, err)
	require.Len(t, resp.Data["keys"].([]string), 10)

	require.Nil(t, readRole(t, b, s, "missing"))

	resp, err = b.HandleRequest(ctx, &logical.Request{Operation: logical.DeleteOperation, Path: "roles/role1", Storage: s})
	requireNoError(t, resp, err)
	require.Nil(t, readRole(t, b, s, "role1"))
}

func TestRoleWritesSerialized(t *testing.T) {
	b, s := getTestBackend(t)
	ctx := context.Background()

	for _, req := range []*logical.Request{
		{Operation: logical.CreateOperation, Path: "roles/r", Storage: s, Data: map[string]interface{}{"permissions": testProjectPermissions}},
		{Operation: logical.DeleteOperation, Path: "roles/r", Storage: s},
	} {
		b.roleLock.Lock()
		done := make(chan struct{})
		go func() {
			defer close(done)
			_, _ = b.HandleRequest(ctx, req)
		}()
		select {
		case <-done:
			t.Fatalf("%s did not wait for the role lock", req.Operation)
		case <-time.After(50 * time.Millisecond):
		}
		b.roleLock.Unlock()
		<-done
	}
	require.Nil(t, readRole(t, b, s, "r"))
}

func TestSealWrapStorage(t *testing.T) {
	b, _ := getTestBackend(t)
	require.ElementsMatch(t, []string{"config", "role/", "wal/"}, b.PathsSpecial.SealWrapStorage)
}

// storedRoleEntry decodes the role from storage, bypassing the ceiling getRole applies.
func storedRoleEntry(t *testing.T, s logical.Storage, name string) *harborRoleEntry {
	t.Helper()
	entry, err := s.Get(context.Background(), roleStoragePrefix+name)
	require.NoError(t, err)
	require.NotNil(t, entry)

	role := new(harborRoleEntry)
	require.NoError(t, entry.DecodeJSON(role))
	return role
}

// TestRoleAllowAllProjectsKeepsStoredIntent pins the ceiling as a reversible disarm: masking the
// flag for callers must not rewrite it, or an unrelated update would erase it for good.
func TestRoleAllowAllProjectsKeepsStoredIntent(t *testing.T) {
	f := newFakeHarbor(t)
	b, s := getTestBackend(t)
	configureMountAllowAllProjects(t, b, s, f, true)

	resp, err := roleRequest(t, b, s, "r", map[string]interface{}{
		"permissions":        testProjectPermissions,
		"allow_all_projects": true,
		"ttl":                "1h",
	})
	requireNoError(t, resp, err)
	require.True(t, storedRoleEntry(t, s, "r").AllowAllProjects)

	configureMountAllowAllProjects(t, b, s, f, false)
	require.Equal(t, false, readRole(t, b, s, "r").Data["allow_all_projects"], "the ceiling masks the flag")

	resp, err = roleRequest(t, b, s, "r", map[string]interface{}{"ttl": "2h"})
	requireNoError(t, resp, err)
	require.True(t, storedRoleEntry(t, s, "r").AllowAllProjects, "an unrelated update must not erase the stored flag")

	configureMountAllowAllProjects(t, b, s, f, true)
	data := readRole(t, b, s, "r").Data
	require.Equal(t, true, data["allow_all_projects"], "raising the mount flag re-arms the role")
	require.Equal(t, (2 * time.Hour).Seconds(), data["ttl"])

	// A request asking for the flag is still refused while the mount forbids it.
	configureMountAllowAllProjects(t, b, s, f, false)
	resp, err = roleRequest(t, b, s, "r", map[string]interface{}{"allow_all_projects": true})
	requireErrorResponse(t, resp, err, "backend configuration")
	require.True(t, storedRoleEntry(t, s, "r").AllowAllProjects)
}
