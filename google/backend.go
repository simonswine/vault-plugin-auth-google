package google

import (
	"fmt"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

// Factory for Google backend.
func Factory(conf *logical.BackendConfig) (logical.Backend, error) {
	b := newBackend()
	if err := b.Setup(conf); err != nil {
		return b, err
	}
	return b, nil
}

const googleBackendHelp = `
The Google credential provider allows you to authenticate with Google.

Documentation can be found at https://github.com/grapeshot/google-auth-vault-plugin.
`

// Backend for google
func newBackend() *backend {
	b := &backend{}

	b.Backend = &framework.Backend{
		BackendType: logical.TypeCredential,
		AuthRenew:   b.authRenew,
		Help:        googleBackendHelp,

		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				loginPath,
				codeURLPath,
			},
		},

		Paths: append([]*framework.Path{
			{
				Pattern: configPath,
				Fields: map[string]*framework.FieldSchema{
					clientIDConfigPropertyName: &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Google application ID",
					},
					clientSecretConfigPropertyName: &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Google application secret",
					},
				},

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
					roleParameterName: {
						Type:        framework.TypeString,
						Description: "Name of the role against which the login is being attempted. Required.",
					},
				},

				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation:         b.pathLogin,
					logical.AliasLookaheadOperation: b.pathLogin,
				},
			},

			{
				Pattern: codeURLPath,
				Fields:  map[string]*framework.FieldSchema{},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.ReadOperation: b.pathCodeURL,
				},
			},

			// CRUD for roles.
			{
				Pattern:        fmt.Sprintf("role/%s", framework.GenericNameRegex("name")),
				Fields:         roleFieldSchema,
				ExistenceCheck: b.pathRoleExistenceCheck,
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.CreateOperation: b.pathRoleCreateUpdate,
					logical.ReadOperation:   b.pathRoleRead,
					logical.UpdateOperation: b.pathRoleCreateUpdate,
					logical.DeleteOperation: b.pathRoleDelete,
				},
				HelpSynopsis:    pathRoleHelpSyn,
				HelpDescription: pathRoleHelpDesc,
			},

			// Paths for listing roles
			{
				Pattern: "role/?",
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.ListOperation: b.pathRoleList,
				},

				HelpSynopsis:    pathListRolesHelpSyn,
				HelpDescription: pathListRolesHelpDesc,
			},
			{
				Pattern: "roles/?",
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.ListOperation: b.pathRoleList,
				},

				HelpSynopsis:    pathListRolesHelpSyn,
				HelpDescription: pathListRolesHelpDesc,
			},
		}),
	}

	return b
}

type backend struct {
	Map *framework.PolicyMap
	*framework.Backend
}
