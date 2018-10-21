package google

import (
	"context"
	"fmt"
	"net/url"
	"path"
	"reflect"
	"strings"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/admin/directory/v1"
	goauth "google.golang.org/api/oauth2/v2"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const (
	configPath  = "config"
	configEntry = "config"

	cliClientIDConfigPropertyName                = "cli_client_id"
	cliClientSecretConfigPropertyName            = "cli_client_secret"
	cliTTLConfigPropertyName                     = "cli_ttl"
	cliMaxTTLConfigPropertyName                  = "cli_max_ttl"
	webClientIDConfigPropertyName                = "web_client_id"
	webClientSecretConfigPropertyName            = "web_client_secret"
	webRedirectURLConfigPropertyName             = "web_redirect_url"
	webTTLConfigPropertyName                     = "web_ttl"
	webMaxTTLConfigPropertyName                  = "web_max_ttl"
	directoryServiceAccountKeyConfigPropertyName = "directory_service_account_key"
	directoryImpersonateUserConfigPropertyName   = "directory_impersonate_user"
	allowedUsersConfigPropertyName               = "allowed_users"
	allowedGroupsConfigPropertyName              = "allowed_groups"
	allowedDomainsConfigPropertyName             = "allowed_domains"
)

func (b *backend) pathConfigWrite(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	// get potentially existing config
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	changed, err := config.update(data)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	if !changed {
		return nil, nil
	}

	entry, err := logical.StorageEntryJSON(configEntry, config)
	if err != nil {
		return nil, err
	}

	return nil, req.Storage.Put(ctx, entry)
}

func (b *backend) pathConfigRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Data: config.mapWithoutSecrets(),
	}, nil
}

// Config returns the configuration for this backend.
func (b *backend) config(ctx context.Context, s logical.Storage) (*config, error) {
	entry, err := s.Get(ctx, configEntry)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return &config{}, nil
	}

	var result config
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, fmt.Errorf("error reading configuration: %s", err)
	}

	/*
		result.WebTTL /= time.Second
		result.WebMaxTTL /= time.Second
		result.CLITTL /= time.Second
		result.CLIMaxTTL /= time.Second
	*/

	return &result, nil
}

type config struct {
	CLIClientID                string        `json:"cli_client_id" description:"Google application ID for CLI oauth2"`
	CLIClientSecret            string        `json:"cli_client_secret" secret:"true" description:"Google application secret for CLI oauth2"`
	CLITTL                     time.Duration `json:"cli_ttl" description:"Duration after which CLI authentication will be expired"`
	CLIMaxTTL                  time.Duration `json:"cli_max_ttl" description:"Maximum duration after which CLI authentication will be expired"`
	WebClientID                string        `json:"web_client_id" description:"Google application ID for Web oauth2"`
	WebClientSecret            string        `json:"web_client_secret" secret:"true" description:"Google application secret for Web oauth2"`
	WebRedirectURL             string        `json:"web_redirect_url" description:"Google redirect URL for Web oauth2"`
	WebTTL                     time.Duration `json:"web_ttl" description:"Duration after which web authentication will be expired"`
	WebMaxTTL                  time.Duration `json:"web_max_ttl" description:"Maximum duration after web which authentication will be expired"`
	DirectoryServiceAccounyKey string        `json:"directory_service_account_key" secret:"true" description:"Google Service Account for Directory Group lookups"`
	DirectoryImpersonateUser   string        `json:"directory_impersonate_user" description:"Google Admin User to Impersonate for Directory Group lookups"`
	AllowedUsers               []string      `json:"allowed_users"`
	AllowedGroups              []string      `json:"allowed_groups"`
	AllowedDomains             []string      `json:"allowed_domains"`
}

func configPathFields() map[string]*framework.FieldSchema {
	output := make(map[string]*framework.FieldSchema)

	c := &config{}
	t := reflect.TypeOf(c).Elem()
	v := reflect.ValueOf(c).Elem()
	for i := 0; i < t.NumField(); i++ {
		tagJSON := t.Field(i).Tag.Get("json")
		tagDescription := t.Field(i).Tag.Get("description")

		// skip fields without json tag
		if tagJSON == "" {
			continue
		}

		val := v.Field(i)
		switch val.Type().String() {
		case "string":
			output[tagJSON] = &framework.FieldSchema{
				Description: tagDescription,
				Type:        framework.TypeString,
			}
		case "time.Duration":
			output[tagJSON] = &framework.FieldSchema{
				Description: tagDescription,
				Type:        framework.TypeDurationSecond,
			}
		case "[]string":
			output[tagJSON] = &framework.FieldSchema{
				Description: tagDescription,
				Type:        framework.TypeCommaStringSlice,
			}
		default:
			panic(fmt.Sprintf("unknown type: %v", val.Type()))
		}

	}

	return output
}

func (c *config) update(data *framework.FieldData) (changed bool, err error) {
	t := reflect.TypeOf(c).Elem()
	v := reflect.ValueOf(c).Elem()
	for i := 0; i < t.NumField(); i++ {
		tagJSON := t.Field(i).Tag.Get("json")

		// skip fields without json tag
		if tagJSON == "" {
			continue
		}

		// get parameter from input data
		param, ok := data.GetOk(tagJSON)

		// skip if not supplied
		if !ok {
			continue
		}

		// update config to new value
		val := v.Field(i)
		switch val.Type().String() {
		case "string":
			s := param.(string)
			if val.String() != s {
				val.SetString(s)
				changed = true
			}
		case "time.Duration":
			value := time.Duration(param.(int)) * time.Second
			if val.Int() != value.Nanoseconds() {
				val.SetInt(value.Nanoseconds())
				changed = true
			}
		case "[]string":
			s := param.([]string)
			if !reflect.DeepEqual(val.Interface().([]string), s) {
				val.Set(reflect.ValueOf(s))
				changed = true
			}
		default:
			return false, fmt.Errorf("unknown type for field '%s': %v", tagJSON, val.Type())
		}
	}
	return changed, nil
}

func (c *config) mapWithoutSecrets() map[string]interface{} {
	output := make(map[string]interface{})

	t := reflect.TypeOf(c).Elem()
	v := reflect.ValueOf(c).Elem()
	for i := 0; i < t.NumField(); i++ {
		tagJSON := t.Field(i).Tag.Get("json")
		tagSecret := t.Field(i).Tag.Get("secret")

		// skip fields without json tag
		if tagJSON == "" {
			continue
		}

		secret := tagSecret == "true"

		val := v.Field(i)

		// if not secret, set value in map
		if !secret {
			if val.Type() == reflect.TypeOf(time.Duration(0)) {
				output[tagJSON] = val.Interface().(time.Duration).String()
			} else {
				output[tagJSON] = val.Interface()
			}
			continue
		}

		// secret non empty strings should be redacted
		switch val.Kind() {
		case reflect.String:
			// skip empty string
			if val.String() == "" {
				output[tagJSON] = ""
			} else {
				output[tagJSON] = "<redacted>"
			}
		}
	}
	return output
}

func (c *config) oauth2Config(authType string) *oauth2.Config {
	config := &oauth2.Config{
		Endpoint: google.Endpoint,
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
			"https://www.googleapis.com/auth/userinfo.profile",
		},
	}

	if authType == typeCLI {
		config.ClientID = c.CLIClientID
		config.ClientSecret = c.CLIClientSecret
		config.RedirectURL = "urn:ietf:wg:oauth:2.0:oob"
	}

	if authType == typeWeb {
		config.ClientID = c.WebClientID
		config.ClientSecret = c.WebClientSecret

		// build redirect URL
		redirectURL, err := url.Parse(c.WebRedirectURL)
		if err != nil {
			redirectURL = &url.URL{Host: "localhost:8200", Scheme: "http"}
		}
		// TODO: support custom path
		mountPath := "google"
		redirectURL.Path = path.Join(redirectURL.Path, "ui/vault/auth/google/callback", mountPath)
		config.RedirectURL = redirectURL.String()
	}

	return config
}

func (c *config) ttlForType(authType string) (ttl time.Duration, maxTTL time.Duration) {
	if authType == typeCLI {
		ttl = c.CLITTL
		maxTTL = c.CLIMaxTTL
	}
	if authType == typeWeb {
		ttl = c.WebTTL
		maxTTL = c.WebMaxTTL
	}
	return ttl, maxTTL
}

func (c *config) authorised(user *goauth.Userinfoplus, groups []*admin.Group) bool {

	// base case, no restrictions configured
	if (len(c.AllowedDomains) + len(c.AllowedGroups) + len(c.AllowedUsers)) == 0 {
		return true
	}

	stringInSliceCaseInsensitive := func(s string, slice []string) bool {
		s = strings.ToLower(s)
		for _, elem := range slice {
			if strings.ToLower(elem) == s {
				return true
			}
		}
		return false
	}

	// allowed by domains
	if stringInSliceCaseInsensitive(user.Hd, c.AllowedDomains) {
		return true
	}

	// allowed by users
	if stringInSliceCaseInsensitive(user.Email, c.AllowedUsers) {
		return true
	}

	// list of groups and aliases of the user
	userGroups := []string{}
	for _, group := range groups {
		userGroups = append(userGroups, group.Email)
		userGroups = append(userGroups, group.Aliases...)
	}

	// check if any allowed group matches
	for _, allowedGroup := range c.AllowedGroups {
		if stringInSliceCaseInsensitive(allowedGroup, userGroups) {
			return true
		}
	}

	return false
}
