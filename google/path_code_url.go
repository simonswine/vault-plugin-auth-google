package google

import (
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"

	"golang.org/x/oauth2"
)

const (
	codeURLPath                 = "code_url"
	codeURLResponsePropertyName = "url"
)

func (b *backend) pathCodeURL(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	config, err := b.config(req.Storage)
	if err != nil {
		return nil, err
	}
	if config == nil {
		return logical.ErrorResponse("missing config"), nil
	}

	authURL := config.oauth2Config().AuthCodeURL("state", oauth2.AccessTypeOffline, oauth2.ApprovalForce)
	return &logical.Response{
		Data: map[string]interface{}{
			codeURLResponsePropertyName: authURL,
		},
	}, nil
}
