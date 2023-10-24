package harbor

import (
	"context"
	"encoding/json"
	"strconv"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"
	"github.com/stretchr/testify/require"

	harborModel "github.com/mittwald/goharbor-client/v5/apiv2/model"
)

const (
	roleName        = "testharbor"
	testTTL         = float64(120)
	testMaxTTL      = float64(3600)
	testPermissions = `
        [
            {
                "namespace":"public",
                "access":
                [
                    {
                        "action": "pull",
                        "resource":"repository"
                    }
                ],
                "kind":"project"
            }
        ]
    `
)

// TestUserRole uses a mock backend to check
// role create, read, update, and delete.
func TestUserRole(t *testing.T) {
	b, s := getTestBackend(t)

	t.Run("List All Roles", func(t *testing.T) {
		for i := 1; i <= 10; i++ {
			_, err := testTokenRoleCreate(t, b, s,
				roleName+strconv.Itoa(i),
				map[string]interface{}{
					"permissions": "[]",
					"ttl":         testTTL,
					"max_ttl":     testMaxTTL,
				})
			require.NoError(t, err)
		}

		resp, err := testTokenRoleList(t, b, s)
		require.NoError(t, err)
		require.Len(t, resp.Data["keys"].([]string), 10)
	})

	t.Run("Create User Role-pass", func(t *testing.T) {
		resp, err := testTokenRoleCreate(t, b, s, roleName, map[string]interface{}{
			"permissions": testPermissions,
			"ttl":         testTTL,
			"max_ttl":     testMaxTTL,
		})

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.Nil(t, resp)
	})

	t.Run("Create User Role-fail", func(t *testing.T) {
		resp, err := testTokenRoleCreate(t, b, s, roleName, map[string]interface{}{
			"ttl":     testTTL,
			"max_ttl": testMaxTTL,
		})

		require.Error(t, err)
		require.Nil(t, resp)
	})

	t.Run("Read User Role", func(t *testing.T) {
		resp, err := testTokenRoleRead(t, b, s)

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.NotNil(t, resp)
		require.Equal(t, testTTL, resp.Data["ttl"])
	})
	t.Run("Update User Role", func(t *testing.T) {
		resp, err := testTokenRoleUpdate(t, b, s, map[string]interface{}{
			"ttl":     "1m",
			"max_ttl": "5h",
		})

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.Nil(t, resp)
	})

	t.Run("Re-read User Role", func(t *testing.T) {
		resp, err := testTokenRoleRead(t, b, s)
		var permissions []harborModel.RobotPermission
		_ = json.Unmarshal([]byte(testPermissions), &permissions)
		expectedPermissions, _ := json.Marshal(permissions)

		require.Nil(t, err)
		require.Nil(t, resp.Error())
		require.NotNil(t, resp)
		require.Equal(t, string(expectedPermissions), resp.Data["permissions"])
	})

	t.Run("Delete User Role", func(t *testing.T) {
		_, err := testTokenRoleDelete(t, b, s)

		require.NoError(t, err)
	})
}

// Utility function to create a role while, returning any response (including errors)
func testTokenRoleCreate(
	t *testing.T,
	b *harborBackend,
	s logical.Storage,
	name string,
	d map[string]interface{},
) (*logical.Response, error) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.CreateOperation,
		Path:      "roles/" + name,
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// Utility function to update a role while, returning any response (including errors)
func testTokenRoleUpdate(t *testing.T, b *harborBackend, s logical.Storage, d map[string]interface{}) (*logical.Response, error) {
	t.Helper()
	resp, err := b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + roleName,
		Data:      d,
		Storage:   s,
	})
	if err != nil {
		return nil, err
	}

	if resp != nil && resp.IsError() {
		t.Fatal(resp.Error())
	}
	return resp, nil
}

// Utility function to read a role and return any errors
func testTokenRoleRead(t *testing.T, b *harborBackend, s logical.Storage) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/" + roleName,
		Storage:   s,
	})
}

// Utility function to list roles and return any errors
func testTokenRoleList(t *testing.T, b *harborBackend, s logical.Storage) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.ListOperation,
		Path:      "roles/",
		Storage:   s,
	})
}

// Utility function to delete a role and return any errors
func testTokenRoleDelete(t *testing.T, b *harborBackend, s logical.Storage) (*logical.Response, error) {
	t.Helper()
	return b.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/" + roleName,
		Storage:   s,
	})
}
