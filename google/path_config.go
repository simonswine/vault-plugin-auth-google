package google

import (
	"fmt"
	"time"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const (
	configPath                     = "config"
	clientIDConfigPropertyName     = "client_id"
	clientSecretConfigPropertyName = "client_secret"
	ttlConfigPropertyName          = "ttl"
	maxTTLConfigPropertyName       = "max_ttl"
	configEntry                    = "config"
)

func (b *backend) pathConfigWrite(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var (
		clientID     = data.Get(clientIDConfigPropertyName).(string)
		clientSecret = data.Get(clientSecretConfigPropertyName).(string)
		ttl          = data.Get(ttlConfigPropertyName).(int)
		maxTTL       = data.Get(maxTTLConfigPropertyName).(int)
	)

	entry, err := logical.StorageEntryJSON(configEntry, config{
		TTL:          time.Duration(ttl) * time.Second,
		MaxTTL:       time.Duration(maxTTL) * time.Second,
		ClientID:     clientID,
		ClientSecret: clientSecret,
	})
	if err != nil {
		return nil, err
	}

	return nil, req.Storage.Put(entry)
}

// Config returns the configuration for this backend.
func (b *backend) config(s logical.Storage) (*config, error) {
	entry, err := s.Get(configEntry)
	if err != nil {
		return nil, err
	}

	var result config
	if err := entry.DecodeJSON(&result); err != nil {
		return nil, fmt.Errorf("error reading configuration: %s", err)
	}

	return &result, nil
}

type config struct {
	ClientID     string        `json:"client_id"`
	ClientSecret string        `json:"client_secret"`
	TTL          time.Duration `json:"ttl"`
	MaxTTL       time.Duration `json:"max_ttl"`
	FetchGroups  bool          `json:"fetch_groups"`
}

func (c *config) oauth2Config() *oauth2.Config {
	config := &oauth2.Config{
		ClientID:     c.ClientID,
		ClientSecret: c.ClientSecret,
		Endpoint:     google.Endpoint,
		RedirectURL:  "urn:ietf:wg:oauth:2.0:oob",
		Scopes: []string{
			"https://www.googleapis.com/auth/userinfo.email",
		},
	}
	if c.FetchGroups {
		config.Scopes = append(config.Scopes, "https://www.googleapis.com/auth/admin.directory.group.readonly")
	}
	return config
}
