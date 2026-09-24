package harbor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	harborModel "github.com/mittwald/goharbor-client/v5/apiv2/model"
)

const (
	pathRoleHelpSynopsis    = `Manages the Vault role for generating Harbor robot accounts.`
	pathRoleHelpDescription = `
This path allows you to read and write roles used to generate Harbor robot accounts.
You can configure a role to manage a robot account's access by setting the permissions field.
`

	pathRoleListHelpSynopsis    = `List the existing roles in Harbor backend`
	pathRoleListHelpDescription = `Roles will be listed by the role name.`

	roleStoragePrefix = "role/"

	// nameRegex is the grammar Harbor enforces for robot and project names; lowercase-only so that
	// ACL policies on roles/<name> and creds/<name> cannot be bypassed by case variants.
	nameRegex = `[a-z0-9]+(?:[._-][a-z0-9]+)*`

	harborNameMaxLen = 255

	robotKindSystem  = "system"
	robotKindProject = "project"

	allProjectsNamespace = "*"

	resourceRepository = "repository"
	actionPull         = "pull"
	actionPush         = "push"
)

var harborNameRegexp = regexp.MustCompile(`^` + nameRegex + `$`)

// allowedAccess is the data-plane subset of Harbor v2.15 robot permissions (src/common/rbac/const.go).
// Everything else changes project settings, reaches external systems (registries, preheat, webhooks)
// or mints principals, escaping the Vault lease lifecycle.
var allowedAccess = map[string]map[string]map[string]bool{
	robotKindProject: {
		"accessory":         {"list": true},
		"artifact":          {"read": true, "list": true, "delete": true},
		"artifact-addition": {"read": true},
		"artifact-label":    {"create": true, "delete": true},
		"label":             {"read": true, "list": true},
		"log":               {"list": true},
		"metadata":          {"read": true, "list": true},
		"project":           {"read": true},
		"quota":             {"read": true},
		"repository":        {"pull": true, "push": true, "list": true, "read": true, "delete": true},
		"sbom":              {"create": true, "read": true, "stop": true},
		"scan":              {"create": true, "read": true, "stop": true},
		"tag":               {"list": true, "create": true, "delete": true},
	},
	// Every system-scope permission Harbor offers reaches the whole registry: "catalog":"read" lists
	// every repository of every project and "project":"list" enumerates every project.
	robotKindSystem: {},
}

// harborRoleEntry defines the data required
// for a Vault role to access and call the Harbor
// robot account endpoints
type harborRoleEntry struct {
	TTL              time.Duration                  `json:"ttl"`
	MaxTTL           time.Duration                  `json:"max_ttl"`
	AllowAllProjects bool                           `json:"allow_all_projects"`
	Permissions      []*harborModel.RobotPermission `json:"permissions"`
}

// toResponseData returns response data for a role
func (r *harborRoleEntry) toResponseData() map[string]interface{} {
	p, _ := json.Marshal(r.Permissions)
	respData := map[string]interface{}{
		"ttl":                r.TTL.Seconds(),
		"max_ttl":            r.MaxTTL.Seconds(),
		"allow_all_projects": r.AllowAllProjects,
		"permissions":        string(p),
	}
	return respData
}

// pathRoles extends the Vault API with a `/roles`
// endpoint for the backend.
func pathRoles(b *harborBackend) []*framework.Path {
	return []*framework.Path{
		{
			Pattern: "roles/(?P<name>" + nameRegex + ")",
			Fields: map[string]*framework.FieldSchema{
				"name": {
					Type:        framework.TypeString,
					Description: "Name of the role",
					Required:    true,
				},
				"permissions": {
					Type:        framework.TypeString,
					Description: "JSON list of Harbor robot permissions",
					Required:    true,
				},
				"ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Default lease for generated credentials. If not set or set to 0, will use system default.",
				},
				"max_ttl": {
					Type:        framework.TypeDurationSecond,
					Description: "Maximum time for role. If not set or set to 0, will use system default.",
				},
				"allow_all_projects": {
					Type:        framework.TypeBool,
					Description: `Allow permissions with the namespace "*", which Harbor grants as a system level robot account on every project, including projects created later`,
				},
			},
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ReadOperation: &framework.PathOperation{
					Callback: b.pathRolesRead,
				},
				logical.CreateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.UpdateOperation: &framework.PathOperation{
					Callback: b.pathRolesWrite,
				},
				logical.DeleteOperation: &framework.PathOperation{
					Callback: b.pathRolesDelete,
				},
			},
			HelpSynopsis:    pathRoleHelpSynopsis,
			HelpDescription: pathRoleHelpDescription,
			ExistenceCheck:  b.pathRoleExistenceCheck,
		},
		{
			Pattern: "roles/?$",
			Operations: map[logical.Operation]framework.OperationHandler{
				logical.ListOperation: &framework.PathOperation{
					Callback: b.pathRolesList,
				},
			},
			HelpSynopsis:    pathRoleListHelpSynopsis,
			HelpDescription: pathRoleListHelpDescription,
		},
	}
}

// pathRoleExistenceCheck verifies if the role exists.
func (b *harborBackend) pathRoleExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	entry, err := b.getRole(ctx, req.Storage, data.Get("name").(string))
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}

	return entry != nil, nil
}

// pathRolesList makes a request to Vault storage to retrieve a list of roles for the backend
func (b *harborBackend) pathRolesList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, roleStoragePrefix)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

// pathRolesRead makes a request to Vault storage to read a role and return response data
func (b *harborBackend) pathRolesRead(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entry, err := b.getRole(ctx, req.Storage, d.Get("name").(string))
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: entry.toResponseData(),
	}, nil
}

// pathRolesWrite makes a request to Vault storage to create or update a role; unspecified fields keep their stored value
func (b *harborBackend) pathRolesWrite(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	name := d.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse("missing role name"), nil
	}

	b.roleLock.Lock()
	defer b.roleLock.Unlock()

	// The stored role, not the view getRole masks, so that an update round-trips what the operator
	// wrote for allow_all_projects instead of erasing it.
	roleEntry, err := getStoredRole(ctx, req.Storage, name)
	if err != nil {
		return nil, err
	}

	permissions, permissionsSet := d.GetOk("permissions")
	if roleEntry == nil {
		if !permissionsSet {
			return logical.ErrorResponse("missing permissions in role"), nil
		}
		roleEntry = &harborRoleEntry{}
	}

	allowAllProjects, allowAllProjectsSet := d.GetOk("allow_all_projects")
	if allowAllProjectsSet {
		roleEntry.AllowAllProjects = allowAllProjects.(bool)
	}

	// Permissions are validated against the effective flag, which is what issuance sees.
	effectiveAllowAllProjects := roleEntry.AllowAllProjects
	if effectiveAllowAllProjects {
		config, err := getConfig(ctx, req.Storage)
		if err != nil {
			return nil, err
		}
		if config == nil || !config.AllowAllProjects {
			// Requesting the flag is refused outright: otherwise a role writer grants itself every
			// project, present and future, in the same request as the permissions, which is the
			// escalation the role flag exists to prevent. A flag already stored is only disarmed,
			// so that raising the mount flag re-arms the role it was written for.
			if allowAllProjectsSet {
				return logical.ErrorResponse("allow_all_projects requires allow_all_projects=true in the backend configuration"), nil
			}
			effectiveAllowAllProjects = false
		}
	}

	if permissionsSet {
		parsedPermissions, err := parsePermissions(permissions.(string), effectiveAllowAllProjects)
		if err != nil {
			return logical.ErrorResponse("invalid permissions: %s", err), nil
		}
		roleEntry.Permissions = parsedPermissions
	} else if err := validatePermissions(roleEntry.Permissions, effectiveAllowAllProjects); err != nil {
		return logical.ErrorResponse("invalid permissions: %s", err), nil
	}

	if ttlRaw, ok := d.GetOk("ttl"); ok {
		roleEntry.TTL = time.Duration(ttlRaw.(int)) * time.Second
	}

	if maxTTLRaw, ok := d.GetOk("max_ttl"); ok {
		roleEntry.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	}

	if systemMaxTTL := b.System().MaxLeaseTTL(); roleEntry.MaxTTL > systemMaxTTL {
		return logical.ErrorResponse("max_ttl %s cannot be greater than the mount max lease TTL %s", roleEntry.MaxTTL, systemMaxTTL), nil
	}

	if roleEntry.MaxTTL != 0 && roleEntry.TTL > roleEntry.MaxTTL {
		return logical.ErrorResponse("ttl cannot be greater than max_ttl"), nil
	}

	if err := setRole(ctx, req.Storage, name, roleEntry); err != nil {
		return nil, err
	}

	return nil, nil
}

// pathRolesDelete makes a request to Vault storage to delete a role
func (b *harborBackend) pathRolesDelete(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	b.roleLock.Lock()
	defer b.roleLock.Unlock()

	err := req.Storage.Delete(ctx, roleStoragePrefix+d.Get("name").(string))
	if err != nil {
		return nil, fmt.Errorf("error deleting harbor role: %w", err)
	}

	return nil, nil
}

// parsePermissions decodes and validates the permissions of a role.
func parsePermissions(raw string, allowAllProjects bool) ([]*harborModel.RobotPermission, error) {
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.DisallowUnknownFields()

	var permissions []*harborModel.RobotPermission
	if err := dec.Decode(&permissions); err != nil {
		return nil, fmt.Errorf("error parsing JSON: %w", err)
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, errors.New("must be exactly one JSON value")
	}

	if err := validatePermissions(permissions, allowAllProjects); err != nil {
		return nil, err
	}

	return permissions, nil
}

// validatePermissions checks permissions against the allowlist. It runs again before every robot
// account is minted, so that a role stored by an earlier version cannot keep minting permissions
// that are no longer allowed.
func validatePermissions(permissions []*harborModel.RobotPermission, allowAllProjects bool) error {
	if len(permissions) == 0 {
		return errors.New("at least one permission is required")
	}

	for i, p := range permissions {
		if p == nil {
			return fmt.Errorf("permission %d is null", i)
		}
		switch p.Kind {
		case robotKindSystem:
			if p.Namespace != "/" {
				return fmt.Errorf(`permission %d: namespace must be "/" for kind system`, i)
			}
		case robotKindProject:
			switch {
			case p.Namespace == allProjectsNamespace:
				if !allowAllProjects {
					return fmt.Errorf("permission %d: namespace %q makes the robot account a system level robot account covering every project, set allow_all_projects=true to allow it", i, allProjectsNamespace)
				}
			case len(p.Namespace) > harborNameMaxLen || !harborNameRegexp.MatchString(p.Namespace):
				return fmt.Errorf("permission %d: namespace must be a valid project name or %q for kind project", i, allProjectsNamespace)
			}
		default:
			return fmt.Errorf(`permission %d: kind must be "system" or "project"`, i)
		}

		if len(allowedAccess[p.Kind]) == 0 {
			return fmt.Errorf("permission %d: kind %s is not supported, no access of that kind is allowed", i, p.Kind)
		}
		if len(p.Access) == 0 {
			return fmt.Errorf("permission %d: access must not be empty", i)
		}
		for j, a := range p.Access {
			if a == nil {
				return fmt.Errorf("permission %d access %d is null", i, j)
			}
			if !allowedAccess[p.Kind][a.Resource][a.Action] {
				return fmt.Errorf("permission %d access %d: resource %q action %q is not allowed for kind %s", i, j, a.Resource, a.Action, p.Kind)
			}
			switch a.Effect {
			case "allow", "":
				// Harbor's robot-creator subset check compares effects verbatim against the creator's own,
				// which are always allow, so a "deny" access is rejected with 403.
				a.Effect = ""
			default:
				return fmt.Errorf(`permission %d access %d: effect must be "allow"`, i, j)
			}
		}
	}

	return nil
}

// withImplicitPull adds repository:pull to every permission granting repository:push. Harbor derives
// the pull from the push for project level robot accounts only (filterRobotPolicies in
// src/common/security/robot/context.go), so a system level one cannot push without it.
func withImplicitPull(permissions []*harborModel.RobotPermission) []*harborModel.RobotPermission {
	out := make([]*harborModel.RobotPermission, len(permissions))
	for i, p := range permissions {
		out[i] = p
		if p == nil {
			continue
		}

		var push, pull bool
		for _, a := range p.Access {
			if a == nil || a.Resource != resourceRepository {
				continue
			}
			switch a.Action {
			case actionPush:
				push = true
			case actionPull:
				pull = true
			}
		}
		if !push || pull {
			continue
		}

		withPull := *p
		withPull.Access = append(append([]*harborModel.Access{}, p.Access...), &harborModel.Access{Resource: resourceRepository, Action: actionPull})
		out[i] = &withPull
	}
	return out
}

// robotLevel returns the Harbor robot level for permissions: Harbor only accepts a
// project-level robot with a single permission on one existing project.
func robotLevel(permissions []*harborModel.RobotPermission) string {
	if len(permissions) == 1 && permissions[0].Kind == robotKindProject && permissions[0].Namespace != "*" {
		return robotKindProject
	}
	return robotKindSystem
}

// setRole adds the role to the Vault storage API
func setRole(ctx context.Context, s logical.Storage, name string, roleEntry *harborRoleEntry) error {
	entry, err := logical.StorageEntryJSON(roleStoragePrefix+name, roleEntry)
	if err != nil {
		return err
	}

	if entry == nil {
		return fmt.Errorf("failed to create storage entry for role")
	}

	if err := s.Put(ctx, entry); err != nil {
		return err
	}

	return nil
}

// getRole gets the role from the Vault storage API
func (b *harborBackend) getRole(ctx context.Context, s logical.Storage, name string) (*harborRoleEntry, error) {
	role, err := getStoredRole(ctx, s, name)
	if err != nil || role == nil {
		return nil, err
	}

	// The backend configuration is the ceiling: a role stored while the mount allowed every project
	// stops granting them as soon as the mount does not, including at issuance time, where
	// validatePermissions then rejects the wildcard namespace. Only this view is masked, so that
	// raising the mount flag re-arms the role without rewriting it.
	if role.AllowAllProjects {
		config, err := getConfig(ctx, s)
		if err != nil {
			return nil, err
		}
		role.AllowAllProjects = config != nil && config.AllowAllProjects
	}

	return role, nil
}

// getStoredRole returns the role exactly as it was written, which only the write path may use: it
// is the one caller that stores the entry again.
func getStoredRole(ctx context.Context, s logical.Storage, name string) (*harborRoleEntry, error) {
	if name == "" {
		return nil, fmt.Errorf("missing role name")
	}

	entry, err := s.Get(ctx, roleStoragePrefix+name)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	var role harborRoleEntry
	if err := entry.DecodeJSON(&role); err != nil {
		return nil, err
	}

	return &role, nil
}
