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
	configPath                          = "config"
	domainConfigPropertyName            = "domain"
	applicationIDConfigPropertyName     = "applicationId"
	applicationSecretConfigPropertyName = "applicationSecret"
	ttlConfigPropertyName               = "ttl"
	maxTTLConfigPropertyName            = "max_ttl"
	configEntry                         = "config"
)

func readDurationFromData(data *framework.FieldData, property string) (time.Duration, *logical.Response) {
	ttlRaw, ok := data.GetOk(property)
	var ttl time.Duration
	var err error
	var rsp *logical.Response
	if !ok || len(ttlRaw.(string)) == 0 {
		ttl = 0
		rsp = nil
	} else {
		ttl, err = time.ParseDuration(ttlRaw.(string))
		if err != nil {
			rsp = logical.ErrorResponse(fmt.Sprintf("Invalid '%s':%s", property, err))
		}
	}
	return ttl, rsp
}

func (b *backend) pathConfigWrite(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var (
		domain            = data.Get(domainConfigPropertyName).(string)
		applicationID     = data.Get(applicationIDConfigPropertyName).(string)
		applicationSecret = data.Get(applicationSecretConfigPropertyName).(string)
		ttl               = data.Get(ttlConfigPropertyName).(time.Duration)
		maxTTL            = data.Get(maxTTLConfigPropertyName).(time.Duration)
	)

	entry, err := logical.StorageEntryJSON(configEntry, config{
		Domain:            domain,
		TTL:               ttl,
		MaxTTL:            maxTTL,
		ApplicationID:     applicationID,
		ApplicationSecret: applicationSecret,
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
	Domain            string        `json:"domain"`
	ApplicationID     string        `json:"applicationId"`
	ApplicationSecret string        `json:"applicationSecret"`
	TTL               time.Duration `json:"ttl"`
	MaxTTL            time.Duration `json:"max_ttl"`
}

func (c *config) oauth2Config() *oauth2.Config {
	return &oauth2.Config{
		ClientID:     c.ApplicationID,
		ClientSecret: c.ApplicationSecret,
		Endpoint:     google.Endpoint,
		RedirectURL:  "urn:ietf:wg:oauth:2.0:oob",
		Scopes:       []string{"email"},
	}
}
