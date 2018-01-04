package google

import (
	"time"

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

	$ vault mount...

You must own a registered Google application.  Configure the Google credential
backend with Application ID and Application Secret first:

  $ vault write auth/google/config applicationId=$GOOGLE_APPLICATION_ID \
      applicationSecret=$GOOGLE_APPLICATION_SECRET \
      domain=example.com

Then, generate a personal access token by browsing to a Google URL, which can
be obtained from the following URL:

  $ vault read auth/google/code_url

Finally, supply this code to vault to login:

  $ vault auth -method=google code=$CODE

The user's google domain will be matched against the domain you configured for
the backend, e.g. example.com (or empty string for none).

Key/Value Pairs:

    mount=google   The mountpoint for the Google credential provider.
                   Defaults to "google"

    code=<code>    The Google access code for authentication.
`

const usersToPoliciesMapPath = "users"

// Backend for google
func newBackend() *backend {
	b := &backend{
		Map: &framework.PolicyMap{
			PathMap: framework.PathMap{
				Name: usersToPoliciesMapPath,
			},
		},
	}

	b.Backend = &framework.Backend{
		Help: googleBackendHelp,

		PathsSpecial: &logical.Paths{
			Unauthenticated: []string{
				loginPath,
				codeURLPath,
			},
		},

		Paths: append([]*framework.Path{
			&framework.Path{
				Pattern: configPath,
				Fields: map[string]*framework.FieldSchema{
					domainConfigPropertyName: &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "The domain users must be part of",
					},
					applicationIDConfigPropertyName: &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Google application ID",
					},
					applicationSecretConfigPropertyName: &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Google application secret",
					},
					ttlConfigPropertyName: &framework.FieldSchema{
						Type:        framework.TypeDurationSecond,
						Description: "Duration after which authentication will be expired",
						Default:     24 * time.Hour,
					},
					maxTTLConfigPropertyName: &framework.FieldSchema{
						Type:        framework.TypeDurationSecond,
						Description: "Maximum duration after which authentication will be expired",
						Default:     24 * time.Hour,
					},
				},

				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathConfigWrite,
				},
			},

			&framework.Path{
				Pattern: loginPath,
				Fields: map[string]*framework.FieldSchema{
					googleAuthCodeParameterName: &framework.FieldSchema{
						Type:        framework.TypeString,
						Description: "Google authentication code",
					},
				},

				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.UpdateOperation: b.pathLogin,
				},
			},

			&framework.Path{
				Pattern: codeURLPath,
				Fields:  map[string]*framework.FieldSchema{},
				Callbacks: map[logical.Operation]framework.OperationFunc{
					logical.ReadOperation: b.pathCodeURL,
				},
			},
		}, b.Map.Paths()...),

		AuthRenew: b.pathLoginRenew,
	}

	return b
}

type backend struct {
	Map *framework.PolicyMap
	*framework.Backend
}
