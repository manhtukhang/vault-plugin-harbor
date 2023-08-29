package harbor

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	harborRobotAccountType = "robot_account"
)

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

// tokenRevoke removes the token from the Vault storage API and calls the client to revoke the robot account
func (b *harborBackend) robotAccountRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	client, err := b.getClient(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if client == nil {
		return nil, fmt.Errorf("error getting Harbor client")
	}

	var account string
	// We passed the account using InternalData from when we first created
	// the secret. This is because the Harbor API uses the exact robot account name
	// for revocation.
	accountRaw, ok := req.Secret.InternalData["robot_account_name"]
	if !ok {
		return nil, fmt.Errorf("robot_account_name is missing on the lease")
	}

	account, ok = accountRaw.(string)
	if !ok {
		return nil, fmt.Errorf("unable convert robot_account_name")
	}

	if err := deleteRobotAccount(ctx, client, account); err != nil {
		return nil, fmt.Errorf("error revoking robot account: %w", err)
	}

	return nil, nil
}

// deleteToken calls the Harbor client to delete the robot account
func deleteRobotAccount(ctx context.Context, c *harborClient, robotAccountName string) error {
	err := c.RESTClient.DeleteRobotAccountByName(ctx, robotAccountName)
	if err != nil {
		return err
	}

	return nil
}

// robotAccountRenew
func (b *harborBackend) robotAccountRenew(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	roleRaw, ok := req.Secret.InternalData["role"]
	if !ok {
		return nil, fmt.Errorf("secret is missing role internal data")
	}

	// get the role entry
	role := roleRaw.(string)
	roleEntry, err := b.getRole(ctx, req.Storage, role)
	if err != nil {
		return nil, fmt.Errorf("error retrieving role: %w", err)
	}

	if roleEntry == nil {
		return nil, errors.New("error retrieving role: role is nil")
	}

	resp := &logical.Response{Secret: req.Secret}

	if roleEntry.TTL > 0 {
		resp.Secret.TTL = roleEntry.TTL
	}
	if roleEntry.MaxTTL > 0 {
		resp.Secret.MaxTTL = roleEntry.MaxTTL
	}

	return resp, nil
}
