package harbor

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

const (
	// pathConfigHelpSynopsis summarizes the help text for the configuration
	pathConfigHelpSynopsis = `Configure the Harbor backend.`

	// pathConfigHelpDescription describes the help text for the configuration
	pathConfigHelpDescription = `
The Harbor secrets backend requires credentials for managing robot accounts.
You must configure the HTTPS URL of Harbor and the username and password of
a principal allowed to create, read, list and delete robot accounts
before using this secrets backend.
`
	configStoragePath = "config"
)

// harborUsernameRegexp is Harbor's robot name grammar widened by the separators of a prefixed robot
// name ("robot$name", "robot$project+name") and by what a local username may hold. Harbor's filter
// parser splits q= on "," and keeps the last value of each key, so a username carrying "," or "="
// would override the Level=system the plugin sends when it looks for its own principal.
var harborUsernameRegexp = regexp.MustCompile(`^[A-Za-z0-9._$+-]{1,255}$`)

// harborRobotPrefixRegexp bounds Harbor's robot_name_prefix, which is prepended to the username and
// reaches the same q= filter, so it excludes "," and "=" for the reason harborUsernameRegexp does.
var harborRobotPrefixRegexp = regexp.MustCompile(`^[A-Za-z0-9._$+-]{1,32}$`)

// harborConfig includes the minimum configuration
// required to instantiate a new Harbor client.
type harborConfig struct {
	Username string `json:"username"`
	Password string `json:"password"`
	URL      string `json:"url"`
	CACert   string `json:"ca_cert"`
	// AllowAllProjects is the mount ceiling for the role field of the same name.
	AllowAllProjects bool `json:"allow_all_projects"`
	// RobotPrefix is Harbor's robot_name_prefix, as written by the operator or measured by rotate-root.
	RobotPrefix string `json:"robot_prefix,omitempty"`
	// RobotID is the Harbor id of the principal when it is a robot account; never returned.
	RobotID int64 `json:"robot_id,omitempty"`
}

// pathConfig extends the Vault API with a `/config`
// endpoint for the backend. You can choose whether
// or not certain attributes should be displayed,
// required, and named. For example, password
// is marked as sensitive and will not be output
// when you read the configuration.
func pathConfig(b *harborBackend) *framework.Path {
	return &framework.Path{
		Pattern: "config",
		Fields: map[string]*framework.FieldSchema{
			"username": {
				Type:        framework.TypeString,
				Description: "The username of the Harbor principal managing robot accounts",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Username",
					Sensitive: false,
				},
			},
			"password": {
				Type:        framework.TypeString,
				Description: "The password or secret of the Harbor principal. Required when changing url or username",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Password",
					Sensitive: true,
				},
			},
			"url": {
				Type:        framework.TypeString,
				Description: "The HTTPS URL of Harbor, e.g. https://harbor.example.com",
				Required:    true,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "URL",
					Sensitive: false,
				},
			},
			"ca_cert": {
				Type:        framework.TypeString,
				Description: "PEM encoded CA certificate(s) trusted in addition to the system roots when connecting to Harbor",
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "CA certificate",
					Sensitive: false,
				},
			},
			"robot_name_prefix": {
				Type:        framework.TypeString,
				Description: `Harbor's robot_name_prefix. Only needed when it contains neither "$" nor "+", such as "bot-", which is otherwise indistinguishable from the name itself`,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Robot name prefix",
					Sensitive: false,
				},
			},
			"allow_all_projects": {
				Type:        framework.TypeBool,
				Description: `Allow roles of this mount to set allow_all_projects, which lets them grant a system level robot account on every project`,
				DisplayAttrs: &framework.DisplayAttributes{
					Name:      "Allow all projects",
					Sensitive: false,
				},
			},
			"verify_connection": {
				Type:        framework.TypeBool,
				Default:     true,
				Description: "Verify the URL and credentials against Harbor before storing the configuration",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathConfigRead,
			},
			logical.CreateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathConfigWrite,
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathConfigDelete,
			},
		},
		ExistenceCheck:  b.pathConfigExistenceCheck,
		HelpSynopsis:    pathConfigHelpSynopsis,
		HelpDescription: pathConfigHelpDescription,
	}
}

// pathConfigExistenceCheck verifies if the configuration exists.
func (b *harborBackend) pathConfigExistenceCheck(ctx context.Context, req *logical.Request, data *framework.FieldData) (bool, error) {
	out, err := req.Storage.Get(ctx, configStoragePath)
	if err != nil {
		return false, fmt.Errorf("existence check failed: %w", err)
	}

	return out != nil, nil
}

// pathConfigRead reads the configuration and outputs non-sensitive information.
func (b *harborBackend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	if config == nil {
		return nil, nil
	}

	return &logical.Response{
		Data: map[string]interface{}{
			"username":           config.Username,
			"url":                config.URL,
			"ca_cert":            config.CACert,
			"robot_name_prefix":  config.RobotPrefix,
			"allow_all_projects": config.AllowAllProjects,
		},
	}, nil
}

// pathConfigWrite updates the configuration for the backend
func (b *harborBackend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.configLock.Lock()
	defer b.configLock.Unlock()

	config, err := getConfig(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	createOperation := (req.Operation == logical.CreateOperation)

	if config == nil {
		if !createOperation {
			return logical.ErrorResponse("config not found during update operation"), nil
		}
		config = new(harborConfig)
	}
	previous := *config

	if username, ok := data.GetOk("username"); ok {
		config.Username = username.(string)
		if !harborUsernameRegexp.MatchString(config.Username) {
			return logical.ErrorResponse(`invalid username: must be 1 to 255 characters of letters, digits and "._$+-"`), nil
		}
	} else if createOperation {
		return logical.ErrorResponse("missing username in configuration"), nil
	}

	if rawURL, ok := data.GetOk("url"); ok {
		normalized, err := normalizeURL(rawURL.(string))
		if err != nil {
			return logical.ErrorResponse("invalid url: %s", err), nil
		}
		config.URL = normalized
	} else if createOperation {
		return logical.ErrorResponse("missing url in configuration"), nil
	}

	if caCert, ok := data.GetOk("ca_cert"); ok {
		config.CACert = strings.TrimSpace(caCert.(string))
		if config.CACert != "" {
			if err := validateCACert(config.CACert); err != nil {
				return logical.ErrorResponse("%s", err), nil
			}
		}
	}

	if allowAllProjects, ok := data.GetOk("allow_all_projects"); ok {
		config.AllowAllProjects = allowAllProjects.(bool)
	}

	password, passwordSet := data.GetOk("password")
	if passwordSet {
		config.Password = password.(string)
	} else if createOperation {
		return logical.ErrorResponse("missing password in configuration"), nil
	}

	// Without this, a config writer could point the stored password at a host they control.
	if config.URL != previous.URL || config.Username != previous.Username {
		if !passwordSet {
			return logical.ErrorResponse("password must be provided when changing url or username"), nil
		}
		// Both describe the principal of the previous url and username.
		config.RobotPrefix = ""
		config.RobotID = 0
	}

	// Written after the reset above, so a request changing the username carries the prefix of the
	// new principal. A rotation measures the prefix from the name Harbor returns and overwrites
	// this value, which only has to cover the prefixes no name can be split on.
	if robotNamePrefix, ok := data.GetOk("robot_name_prefix"); ok {
		prefix := robotNamePrefix.(string)
		if prefix != "" && !harborRobotPrefixRegexp.MatchString(prefix) {
			return logical.ErrorResponse(`invalid robot_name_prefix: must be at most 32 characters of letters, digits and "._$+-"`), nil
		}
		config.RobotPrefix = prefix
	}

	if config.Username == "" || config.Password == "" {
		return logical.ErrorResponse("username and password must not be empty"), nil
	}

	var warnings []string
	if data.Get("verify_connection").(bool) {
		client, err := newClient(config)
		if err != nil {
			return logical.ErrorResponse("%s", err), nil
		}
		defer client.http.CloseIdleConnections()
		if err := client.verifyConnection(ctx); err != nil {
			return logical.ErrorResponse("failed to verify connection to Harbor: %s", err), nil
		}
		// Identity, not name, is what keeps a rollback from deleting the live principal.
		if robot, err := findRobotPrincipal(ctx, client, config); err != nil {
			b.Logger().Warn("failed to resolve the configured Harbor principal", "error", err)
		} else if robot != nil {
			config.RobotID = robot.ID
		} else {
			warnings = b.principalWarnings(ctx, client, config.Username)
		}
	}

	if err := storeConfig(ctx, req.Storage, config); err != nil {
		return nil, err
	}

	// reset the client so the next invocation will pick up the new configuration
	b.reset()

	if len(warnings) == 0 {
		return nil, nil
	}

	return &logical.Response{Warnings: warnings}, nil
}

// pathConfigDelete removes the configuration for the backend
func (b *harborBackend) pathConfigDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.configLock.Lock()
	defer b.configLock.Unlock()

	err := req.Storage.Delete(ctx, configStoragePath)

	if err == nil {
		b.reset()
	}

	return nil, err
}

func storeConfig(ctx context.Context, s logical.Storage, config *harborConfig) error {
	entry, err := logical.StorageEntryJSON(configStoragePath, config)
	if err != nil {
		return err
	}
	return s.Put(ctx, entry)
}

func getConfig(ctx context.Context, s logical.Storage) (*harborConfig, error) {
	entry, err := s.Get(ctx, configStoragePath)
	if err != nil {
		return nil, err
	}

	if entry == nil {
		return nil, nil
	}

	config := new(harborConfig)
	if err := entry.DecodeJSON(&config); err != nil {
		return nil, fmt.Errorf("error reading root configuration: %w", err)
	}

	// return the config, we are done
	return config, nil
}

// principalWarnings reports a principal Harbor does not bound. Harbor's creator-subset check, which
// limits an issued robot account to the permissions of the robot account creating it, is the
// server-side ceiling on what a role can grant, and it binds robot principals only.
func (b *harborBackend) principalWarnings(ctx context.Context, client *harborClient, username string) []string {
	user, err := client.GetCurrentUser(ctx)
	if err != nil {
		// Harbor refuses this call for a robot principal, including one whose own listing of system
		// robot accounts is forbidden, which is why it is not evidence of a user principal.
		b.Logger().Debug("failed to read the current Harbor user", "error", err)
		return nil
	}

	warnings := []string{fmt.Sprintf("the Harbor principal %q is not a robot account, so Harbor does not limit the robot accounts it creates to its own permissions and the role allowlist is the only ceiling", username)}
	if user.SysadminFlag {
		warnings = append(warnings, fmt.Sprintf("the Harbor principal %q is a Harbor system administrator, which puts every project and every Harbor setting in reach of this mount", username))
	}

	return warnings
}

// normalizeURL validates a Harbor URL and returns it without trailing "/" or "/api/v2.0".
// Errors never echo the input, which may carry credentials.
func normalizeURL(raw string) (string, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return "", errors.New("url cannot be parsed")
	}
	if u.Scheme != "https" {
		return "", errors.New("url scheme must be https")
	}
	if u.Opaque != "" || u.Hostname() == "" {
		return "", errors.New("url must include a host")
	}
	if u.User != nil {
		return "", errors.New("url must not contain credentials")
	}
	if u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return "", errors.New("url must not contain a query or fragment")
	}

	path := strings.TrimRight(u.Path, "/")
	path = strings.TrimSuffix(path, harborAPIPath)
	u.Path = strings.TrimRight(path, "/")
	u.RawPath = ""
	u.Host = strings.TrimSuffix(strings.ToLower(u.Host), ":443")

	return u.String(), nil
}
