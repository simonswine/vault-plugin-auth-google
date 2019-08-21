package google

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

// Factory for Google backend.
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := newBackend()
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

const googleBackendHelp = `
The Google credential provider allows you to authenticate with Google.

Documentation can be found at https://github.com/grapeshot/google-auth-vault-plugin.
`

// Backend for google
func newBackend() *backend {
	gp := &googleProvider{}
	b := &backend{
		user:   gp,
		groups: gp,
	}

	b.Backend = &framework.Backend{
		BackendType: logical.TypeCredential,
		AuthRenew:   b.pathRenew,
		Help:        googleBackendHelp,

		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				loginPath,
				cliCodeURLPath,
				webCodeURLPath,
			},
		},

		Paths: append([]*framework.Path{
			{
				Pattern: configPath,
				Fields:  configPathFields(),

				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathConfigWrite,
					logical.ReadOperation:   b.pathConfigRead,
				},
			},

			{
				Pattern: loginPath,
				Fields: map[string]*framework.FieldSchema{
					googleAuthCodeParameterName: &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Google authentication code. Required.",
					},
					stateParameterName: {
						Type:        framework.TypeString,
						Description: "State parameter used by web login. If used the web method is used. Optional.",
					},
				},

				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation:         b.pathLogin,
					logical.AliasLookaheadOperation: b.pathLogin,
				},
			},

			{
				Pattern: cliCodeURLPath,
				Fields:  map[string]*framework.FieldSchema{},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.ReadOperation: b.pathCLICodeURL,
				},
			},

			{
				Pattern: webCodeURLPath,
				Fields:  map[string]*framework.FieldSchema{},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.ReadOperation: b.pathWebCodeURL,
				},
			},
		}),
	}

	return b
}

type backend struct {
	Map *framework.PolicyMap
	*framework.Backend

	user   UserProvider
	groups GroupsProvider
}
