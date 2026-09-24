package harbor

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"

	harborModel "github.com/mittwald/goharbor-client/v5/apiv2/model"
)

func generateCAPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func configRequest(t *testing.T, b *harborBackend, s logical.Storage, data map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	req := &logical.Request{Path: configStoragePath, Storage: s, Data: data}
	return handleWrite(t, b, req)
}

func readConfig(t *testing.T, b *harborBackend, s logical.Storage) *logical.Response {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      configStoragePath,
		Storage:   s,
	})
	require.NoError(t, err)
	return resp
}

func TestConfigReadBeforeWrite(t *testing.T) {
	b, s := getTestBackend(t)
	require.Nil(t, readConfig(t, b, s))
}

func TestConfigLifecycle(t *testing.T) {
	f := newFakeHarbor(t)
	other := newFakeHarbor(t)
	b, s := getTestBackend(t)

	_, exists, err := b.HandleExistenceCheck(context.Background(), &logical.Request{Operation: logical.CreateOperation, Path: configStoragePath, Storage: s})
	require.NoError(t, err)
	require.False(t, exists)

	resp, err := configRequest(t, b, s, map[string]interface{}{
		"url":      f.URL() + "/api/v2.0/",
		"username": fakeHarborUsername,
		"password": fakeHarborPassword,
		"ca_cert":  f.CACert(),
	})
	requireNoError(t, resp, err)
	require.Contains(t, f.requestLog(), "GET /api/v2.0/robots?page=1&page_size=1")

	_, exists, err = b.HandleExistenceCheck(context.Background(), &logical.Request{Operation: logical.CreateOperation, Path: configStoragePath, Storage: s})
	require.NoError(t, err)
	require.True(t, exists)

	resp = readConfig(t, b, s)
	require.Equal(t, map[string]interface{}{
		"username":           fakeHarborUsername,
		"url":                f.URL(),
		"ca_cert":            strings.TrimSpace(f.CACert()),
		"robot_name_prefix":  "",
		"allow_all_projects": false,
	}, resp.Data)

	t.Run("same url without password", func(t *testing.T) {
		resp, err := configRequest(t, b, s, map[string]interface{}{"url": f.URL() + "/"})
		requireNoError(t, resp, err)
	})

	// Rotating the CA must stay possible after rotate-root, where nobody knows the password.
	t.Run("change ca_cert without password", func(t *testing.T) {
		resp, err := configRequest(t, b, s, map[string]interface{}{"ca_cert": generateCAPEM(t) + f.CACert()})
		requireNoError(t, resp, err)
		require.NotEqual(t, strings.TrimSpace(f.CACert()), readConfig(t, b, s).Data["ca_cert"])

		resp, err = configRequest(t, b, s, map[string]interface{}{"ca_cert": f.CACert()})
		requireNoError(t, resp, err)
		require.Equal(t, strings.TrimSpace(f.CACert()), readConfig(t, b, s).Data["ca_cert"])
	})

	for name, data := range map[string]map[string]interface{}{
		"url":      {"url": other.URL()},
		"username": {"username": "robot$other"},
	} {
		t.Run("change "+name+" without password", func(t *testing.T) {
			resp, err := configRequest(t, b, s, data)
			requireErrorResponse(t, resp, err, "password must be provided")
		})
	}

	resp = readConfig(t, b, s)
	require.Equal(t, f.URL(), resp.Data["url"])

	t.Run("change url with password", func(t *testing.T) {
		resp, err := configRequest(t, b, s, map[string]interface{}{
			"url":      other.URL(),
			"password": fakeHarborPassword,
		})
		requireNoError(t, resp, err)
		require.Equal(t, other.URL(), readConfig(t, b, s).Data["url"])
	})

	t.Run("delete", func(t *testing.T) {
		resp, err := b.HandleRequest(context.Background(), &logical.Request{
			Operation: logical.DeleteOperation,
			Path:      configStoragePath,
			Storage:   s,
		})
		requireNoError(t, resp, err)
		require.Nil(t, readConfig(t, b, s))
	})
}

func TestConfigValidation(t *testing.T) {
	f := newFakeHarbor(t)

	valid := func() map[string]interface{} {
		return map[string]interface{}{
			"url":               f.URL(),
			"username":          fakeHarborUsername,
			"password":          fakeHarborPassword,
			"verify_connection": false,
		}
	}

	cases := map[string]struct {
		mutate   func(map[string]interface{})
		contains string
	}{
		"http url":         {func(d map[string]interface{}) { d["url"] = "http://harbor.example.com" }, "https"},
		"url credentials":  {func(d map[string]interface{}) { d["url"] = "https://admin:S3cret@harbor.example.com" }, "credentials"},
		"missing url":      {func(d map[string]interface{}) { delete(d, "url") }, "missing url"},
		"missing username": {func(d map[string]interface{}) { delete(d, "username") }, "missing username"},
		"missing password": {func(d map[string]interface{}) { delete(d, "password") }, "missing password"},
		"empty password":   {func(d map[string]interface{}) { d["password"] = "" }, "must not be empty"},
		"invalid ca_cert": {func(d map[string]interface{}) {
			d["ca_cert"] = "-----BEGIN CERTIFICATE-----\nnope\n-----END CERTIFICATE-----"
		}, "ca_cert"},
		"wrong password verified": {func(d map[string]interface{}) {
			d["password"] = "Wrong-Password-1"
			d["ca_cert"] = f.CACert()
			d["verify_connection"] = true
		}, "HTTP 401"},
		"untrusted certificate verified": {func(d map[string]interface{}) { d["verify_connection"] = true }, "certificate"},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			b, s := getTestBackend(t)
			data := valid()
			tc.mutate(data)
			resp, err := configRequest(t, b, s, data)
			requireErrorResponse(t, resp, err, tc.contains)
			require.NotContains(t, resp.Error().Error(), "S3cret")
			require.NotContains(t, resp.Error().Error(), fakeHarborPassword)
			require.Nil(t, readConfig(t, b, s))
		})
	}

	t.Run("valid without verification", func(t *testing.T) {
		b, s := getTestBackend(t)
		requests := len(f.requestLog())
		resp, err := configRequest(t, b, s, valid())
		requireNoError(t, resp, err)
		require.Len(t, f.requestLog(), requests)
	})
}

func TestConfigUpdateWithoutConfig(t *testing.T) {
	b, s := getTestBackend(t)
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      configStoragePath,
		Storage:   s,
		Data:      map[string]interface{}{"username": "u"},
	})
	requireErrorResponse(t, resp, err, "config not found")
}

func TestConfigUsernameValidation(t *testing.T) {
	f := newFakeHarbor(t)

	write := func(t *testing.T, b *harborBackend, s logical.Storage, username string) (*logical.Response, error) {
		t.Helper()
		return configRequest(t, b, s, map[string]interface{}{
			"url":               f.URL(),
			"username":          username,
			"password":          fakeHarborPassword,
			"verify_connection": false,
		})
	}

	// Harbor's filter parser splits q= on ",", keeps the last value of each key and unescapes
	// twice, so a username carrying "," or "=" rewrites the Level=system filter the plugin sends.
	invalid := map[string]string{
		"filter injection":         `robot$a,Level=project,ProjectID=1`,
		"escaped filter injection": `robot$a%2CLevel%3Dproject`,
		"equals":                   "robot$a=b",
		"space":                    "robot$a b",
		"newline":                  "robot$a\nb",
		"slash":                    "robot$a/b",
		"empty":                    "",
		"too long":                 strings.Repeat("a", 256),
	}
	for name, username := range invalid {
		t.Run(name, func(t *testing.T) {
			b, s := getTestBackend(t)
			resp, err := write(t, b, s, username)
			requireErrorResponse(t, resp, err, "username")
			require.Nil(t, readConfig(t, b, s))
		})
	}

	for _, username := range []string{fakeHarborUsername, "robot$library+ci", "robot_vault.r1", "vault-admin", "a.b_c-d", strings.Repeat("a", 255)} {
		b, s := getTestBackend(t)
		resp, err := write(t, b, s, username)
		requireNoError(t, resp, err)
		require.Equal(t, username, readConfig(t, b, s).Data["username"])
	}

	t.Run("update keeps the stored username", func(t *testing.T) {
		b, s := getTestBackend(t)
		resp, err := write(t, b, s, fakeHarborUsername)
		requireNoError(t, resp, err)

		resp, err = write(t, b, s, `robot$a,Level=project,ProjectID=1`)
		requireErrorResponse(t, resp, err, "username")
		require.Equal(t, fakeHarborUsername, readConfig(t, b, s).Data["username"])
	})
}

func TestConfigAllowAllProjects(t *testing.T) {
	f := newFakeHarbor(t)
	b, s := getTestBackend(t)

	resp, err := configRequest(t, b, s, map[string]interface{}{
		"url":               f.URL(),
		"username":          fakeHarborUsername,
		"password":          fakeHarborPassword,
		"verify_connection": false,
	})
	requireNoError(t, resp, err)
	require.Equal(t, false, readConfig(t, b, s).Data["allow_all_projects"])

	for _, allow := range []bool{true, false} {
		resp, err := configRequest(t, b, s, map[string]interface{}{
			"allow_all_projects": allow,
			"verify_connection":  false,
		})
		requireNoError(t, resp, err)
		require.Equal(t, allow, readConfig(t, b, s).Data["allow_all_projects"])
	}
}

func TestConfigCACertBundle(t *testing.T) {
	f := newFakeHarbor(t)
	valid := generateCAPEM(t)
	// AppendCertsFromPEM decodes this block and drops it without failing.
	corrupt := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")}))
	key := string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: []byte("not a key either")}))

	cases := map[string]struct {
		caCert   string
		contains string
	}{
		"corrupt intermediate": {valid + corrupt, "cannot be parsed"},
		"corrupt first":        {corrupt + valid, "cannot be parsed"},
		"private key block":    {valid + key, "EC PRIVATE KEY"},
		"trailing garbage":     {valid + "oops\n", "not PEM encoded"},
		"no certificate":       {"not a certificate\n", "not PEM encoded"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			b, s := getTestBackend(t)
			resp, err := configRequest(t, b, s, map[string]interface{}{
				"url":               f.URL(),
				"username":          fakeHarborUsername,
				"password":          fakeHarborPassword,
				"ca_cert":           tc.caCert,
				"verify_connection": false,
			})
			requireErrorResponse(t, resp, err, tc.contains)
			require.Nil(t, readConfig(t, b, s))
		})
	}

	for name, caCert := range map[string]string{"single": valid, "bundle": valid + generateCAPEM(t)} {
		t.Run(name, func(t *testing.T) {
			b, s := getTestBackend(t)
			resp, err := configRequest(t, b, s, map[string]interface{}{
				"url":               f.URL(),
				"username":          fakeHarborUsername,
				"password":          fakeHarborPassword,
				"ca_cert":           caCert,
				"verify_connection": false,
			})
			requireNoError(t, resp, err)
			require.Equal(t, strings.TrimSpace(caCert), readConfig(t, b, s).Data["ca_cert"])
		})
	}
}

// userPrincipalHarbor answers the calls a verified config write makes, as a Harbor whose principal
// is the given user; the shared fake cannot report a sysadmin.
func userPrincipalHarbor(t *testing.T, user *harborModel.UserResp) *httptest.Server {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2.0/robots":
			w.Header().Set("X-Total-Count", "0")
			writeJSON(w, http.StatusOK, []*harborModel.Robot{})
		case "/api/v2.0/users/current":
			writeJSON(w, http.StatusOK, user)
		default:
			writeHarborError(w, http.StatusNotFound, "not found")
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestConfigPrincipalWarnings(t *testing.T) {
	t.Run("robot", func(t *testing.T) {
		f := newFakeHarbor(t)
		b, s := getTestBackend(t)
		resp, err := configRequest(t, b, s, map[string]interface{}{
			"url":      f.URL(),
			"username": fakeHarborUsername,
			"password": fakeHarborPassword,
			"ca_cert":  f.CACert(),
		})
		requireNoError(t, resp, err)
		require.Nil(t, resp)
	})

	cases := map[string]struct {
		user     *harborModel.UserResp
		warnings []string
	}{
		"user":     {&harborModel.UserResp{UserID: 1, Username: "vault-admin"}, []string{"not a robot account"}},
		"sysadmin": {&harborModel.UserResp{UserID: 1, Username: "admin", SysadminFlag: true}, []string{"not a robot account", "system administrator"}},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			srv := userPrincipalHarbor(t, tc.user)
			b, s := getTestBackend(t)

			resp, err := configRequest(t, b, s, map[string]interface{}{
				"url":      srv.URL,
				"username": tc.user.Username,
				"password": fakeHarborPassword,
				"ca_cert":  string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})),
			})
			requireNoError(t, resp, err)
			require.Len(t, resp.Warnings, len(tc.warnings))
			for i, contains := range tc.warnings {
				require.Contains(t, resp.Warnings[i], contains)
				require.Contains(t, resp.Warnings[i], tc.user.Username)
			}
			require.Equal(t, tc.user.Username, readConfig(t, b, s).Data["username"])
		})
	}
}

func TestConfigRobotNamePrefix(t *testing.T) {
	f := newFakeHarbor(t)

	write := func(t *testing.T, b *harborBackend, s logical.Storage, prefix string) (*logical.Response, error) {
		t.Helper()
		return configRequest(t, b, s, map[string]interface{}{
			"url":               f.URL(),
			"username":          fakeHarborUsername,
			"password":          fakeHarborPassword,
			"robot_name_prefix": prefix,
			"verify_connection": false,
		})
	}

	invalid := map[string]string{
		"comma":    "bot,",
		"equals":   "bot=",
		"space":    "bot -",
		"too long": strings.Repeat("a", 33),
	}
	for name, prefix := range invalid {
		t.Run(name, func(t *testing.T) {
			b, s := getTestBackend(t)
			resp, err := write(t, b, s, prefix)
			requireErrorResponse(t, resp, err, "robot_name_prefix")
			require.Nil(t, readConfig(t, b, s))
		})
	}

	for _, prefix := range []string{"", "robot$", "robot_", "bot-", "harbor.bot+"} {
		b, s := getTestBackend(t)
		resp, err := write(t, b, s, prefix)
		requireNoError(t, resp, err)
		require.Equal(t, prefix, readConfig(t, b, s).Data["robot_name_prefix"])
	}

	t.Run("kept when another field changes", func(t *testing.T) {
		b, s := getTestBackend(t)
		resp, err := write(t, b, s, "bot-")
		requireNoError(t, resp, err)

		resp, err = configRequest(t, b, s, map[string]interface{}{"ca_cert": f.CACert(), "verify_connection": false})
		requireNoError(t, resp, err)
		require.Equal(t, "bot-", readConfig(t, b, s).Data["robot_name_prefix"])
	})

	t.Run("cleared when the username changes", func(t *testing.T) {
		b, s := getTestBackend(t)
		resp, err := write(t, b, s, "bot-")
		requireNoError(t, resp, err)

		resp, err = configRequest(t, b, s, map[string]interface{}{
			"username":          "bot-other",
			"password":          fakeHarborPassword,
			"verify_connection": false,
		})
		requireNoError(t, resp, err)
		require.Equal(t, "", readConfig(t, b, s).Data["robot_name_prefix"])
	})
}

// TestConfigRobotNamePrefixLifecycle mints and revokes a system level robot account on a Harbor
// whose robot_name_prefix carries neither "$" nor "+", which identity matching cannot recover from
// the name alone and a rotation cannot record first.
func TestConfigRobotNamePrefixLifecycle(t *testing.T) {
	ctx := context.Background()
	f := newFakeHarbor(t)
	f.setPrefix("bot-")
	principal := f.addPrincipalRobot("vault", 30, nil)
	b, s := getTestBackend(t)

	resp, err := configRequest(t, b, s, map[string]interface{}{
		"url":                f.URL(),
		"username":           "bot-vault",
		"password":           fakeHarborPassword,
		"ca_cert":            f.CACert(),
		"robot_name_prefix":  "bot-",
		"allow_all_projects": true,
	})
	requireNoError(t, resp, err)
	require.Equal(t, "bot-", readConfig(t, b, s).Data["robot_name_prefix"])

	resp, err = roleRequest(t, b, s, "ci", map[string]interface{}{
		"permissions":        testSystemPermissions,
		"allow_all_projects": true,
	})
	requireNoError(t, resp, err)

	resp, err = b.HandleRequest(ctx, &logical.Request{
		Operation:   logical.ReadOperation,
		Path:        "creds/ci",
		Storage:     s,
		DisplayName: "token-test",
	})
	requireNoError(t, resp, err)

	id := resp.Data["robot_account_id"].(int64)
	require.NotEqual(t, principal, id)
	require.Equal(t, robotKindSystem, f.lastCreate().Level)
	robot, found := f.robot(id)
	require.True(t, found)
	require.True(t, strings.HasPrefix(robot.Name, "bot-"))

	resp, err = b.HandleRequest(ctx, &logical.Request{Operation: logical.RevokeOperation, Storage: s, Secret: resp.Secret})
	requireNoError(t, resp, err)
	_, found = f.robot(id)
	require.False(t, found, "the robot account must be deleted despite the unseparated prefix")
	require.Equal(t, []int64{id}, f.deletedIDs())
}
