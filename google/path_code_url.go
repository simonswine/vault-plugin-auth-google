package google

import (
	"context"
	"encoding/base64"
	"fmt"
	"time"

	"github.com/hashicorp/go-uuid"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/framework"
	"golang.org/x/oauth2"
)

const (
	webCodeURLPath              = "web_code_url"
	cliCodeURLPath              = "cli_code_url"
	codeURLResponsePropertyName = "url"
	typeWeb                     = "web"
	typeCLI                     = "cli"
)

type state struct {
	Type    string    `json:"type"` // web or cli
	Created time.Time `json:"created"`
}

func (b *backend) statePath(stateValue string) string {
	return fmt.Sprintf("state/%s", stateValue)
}

func (b *backend) cleanupStates(ctx context.Context, req *logical.Request) error {
	statePaths, err := req.Storage.List(ctx, b.statePath(""))
	if err != nil {
		return err
	}

	deadline := time.Now().Add(-24 * time.Hour)

	for _, statePath := range statePaths {
		state, err := b.state(ctx, req, statePath)
		if err != nil {
			return err
		}
		if state == nil {
			continue
		}

		// keep states younger than 24 hours
		if state.Created.After(deadline) {
			continue
		}

		if err := b.deleteState(ctx, req, statePath); err != nil {
			return err
		}
	}
	return nil
}

func (b *backend) deleteState(ctx context.Context, req *logical.Request, statePath string) error {
	return req.Storage.Delete(ctx, statePath)
}

func (b *backend) state(ctx context.Context, req *logical.Request, statePath string) (*state, error) {
	// try to get state
	entry, err := req.Storage.Get(ctx, statePath)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var stateObj = &state{}

	if err := entry.DecodeJSON(stateObj); err != nil {
		return nil, fmt.Errorf("error reading state: %s", err)
	}

	return stateObj, nil
}

// return URL for cli oauth2 flow
func (b *backend) pathCLICodeURL(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathCodeURL(ctx, req, data, typeCLI)
}

// return URL for web oauth2 flow
func (b *backend) pathWebCodeURL(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	return b.pathCodeURL(ctx, req, data, typeWeb)
}

// generic
func (b *backend) pathCodeURL(ctx context.Context, req *logical.Request, data *framework.FieldData, authType string) (*logical.Response, error) {
	config, err := b.config(ctx, req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse("missing config"), nil
	}

	errUnknown := fmt.Errorf("unknown auth type: %s", authType)

	var oauth2Options = []oauth2.AuthCodeOption{oauth2.ApprovalForce}
	switch authType {
	case typeWeb:
		if config.WebClientID == "" || config.WebClientSecret == "" || config.WebRedirectURL == "" {
			return logical.ErrorResponse("missing config for web oauth2 client"), nil
		}
	case typeCLI:
		if config.CLIClientID == "" || config.CLIClientSecret == "" {
			return logical.ErrorResponse("missing config for CLI oauth2 client"), nil
		}
		oauth2Options = append(oauth2Options, oauth2.AccessTypeOffline)
	default:
		return nil, errUnknown
	}

	oauth2Config := config.oauth2Config(authType)

	stateNonceByte, err := uuid.GenerateRandomBytes(16)
	if err != nil {
		return nil, err
	}
	stateNonce := base64.URLEncoding.EncodeToString(stateNonceByte)
	stateObj := &state{
		Created: time.Now(),
		Type:    authType,
	}

	entry, err := logical.StorageEntryJSON(fmt.Sprintf("state/%s", stateNonce), stateObj)
	if err != nil {
		return nil, err
	}

	// store object
	if err := req.Storage.Put(ctx, entry); err != nil {
		return nil, err
	}

	authURL := oauth2Config.AuthCodeURL(stateNonce, oauth2Options...)
	return &logical.Response{
		Data: map[string]interface{}{
			codeURLResponsePropertyName: authURL,
			stateParameterName:          stateNonce,
		},
	}, nil
}
