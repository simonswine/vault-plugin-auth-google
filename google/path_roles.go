package google

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/hashicorp/vault/helper/policyutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const (
	pathRoleHelpSyn  = `Create a Google role with associated policies and required attributes.`
	pathRoleHelpDesc = `
A role is required to login under the Google auth backend. A role binds Vault policies and has
required attributes that an authenticating entity must fulfill to login against this role.
After authenticating the instance, Vault uses the bound policies to determine which resources
the authorization token for the instance can access.
`

	pathListRolesHelpSyn  = `Lists all the roles that are registered with Vault.`
	pathListRolesHelpDesc = `Lists all roles under the Google backends by name.`

	errEmptyRoleName = "role name is required"
	errEmptyDomain   = "bound domain cannot be empty"
)

var roleFieldSchema = map[string]*framework.FieldSchema{
	"name": {
		Type:        framework.TypeString,
		Description: "Name of the role.",
	},
	"policies": {
		Type:        framework.TypeCommaStringSlice,
		Description: "Policies to be set on tokens issued using this role.",
	},
	"bound_domain": {
		Type:        framework.TypeString,
		Description: "The domain users must be a member of to grant this role.",
	},
	"bound_groups": {
		Type:        framework.TypeCommaStringSlice,
		Description: "Comma separate list of groups, at least one of which the user must be in to grant this role.",
	},
	// Token Limits
	"ttl": {
		Type:    framework.TypeDurationSecond,
		Default: 0,
		Description: `
	Duration in seconds after which the issued token should expire. Defaults to 0,
	in which case the value will fallback to the system/mount defaults.`,
	},
	"max_ttl": {
		Type:        framework.TypeDurationSecond,
		Default:     0,
		Description: "The maximum allowed lifetime of tokens issued using this role.",
	},
	"period": {
		Type:    framework.TypeDurationSecond,
		Default: 0,
		Description: `
	If set, indicates that the token generated using this role should never expire. The token should be renewed within the
	duration specified by this value. At each renewal, the token's TTL will be set to the value of this parameter.`,
	},
}

func (b *backend) pathRoleExistenceCheck(req *logical.Request, data *framework.FieldData) (bool, error) {
	entry, err := b.role(req.Storage, data.Get("name").(string))
	if err != nil {
		return false, err
	}
	return entry != nil, nil
}

func (b *backend) pathRoleDelete(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse(errEmptyRoleName), nil
	}

	if err := req.Storage.Delete(fmt.Sprintf("role/%s", name)); err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathRoleRead(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := data.Get("name").(string)
	if name == "" {
		return logical.ErrorResponse(errEmptyRoleName), nil
	}

	role, err := b.role(req.Storage, name)
	if err != nil {
		return nil, err
	} else if role == nil {
		return nil, nil
	}

	roleMap := map[string]interface{}{
		"policies":      role.Policies,
		"bound_domain":  role.BoundDomain,
		"bound_groupds": role.BoundGroups,
		"ttl":           int64(role.TTL / time.Second),
		"max_ttl":       int64(role.MaxTTL / time.Second),
		"period":        int64(role.Period / time.Second),
	}

	return &logical.Response{
		Data: roleMap,
	}, nil
}

func (b *backend) pathRoleCreateUpdate(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	name := strings.ToLower(data.Get("name").(string))
	if name == "" {
		return logical.ErrorResponse(errEmptyRoleName), nil
	}

	r, err := b.role(req.Storage, name)
	if err != nil {
		return nil, err
	}
	if r == nil {
		r = &role{}
	}

	if err := r.updateRole(b.System(), req.Operation, data); err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	return b.storeRole(req.Storage, name, r)
}

func (b *backend) pathRoleList(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roles, err := req.Storage.List("role/")
	if err != nil {
		return nil, err
	}
	return logical.ListResponse(roles), nil
}

// role reads a role from storage.  Returns nil, nil if the role doesn't exist.
func (b *backend) role(s logical.Storage, name string) (*role, error) {
	entry, err := s.Get(fmt.Sprintf("role/%s", name))
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	role := &role{}
	if err := entry.DecodeJSON(role); err != nil {
		return nil, err
	}

	return role, nil
}

// storeRole saves the role to storage.
// The returned response may contain either warnings or an error response,
// but will be nil if error is not nil
func (b *backend) storeRole(s logical.Storage, roleName string, role *role) (*logical.Response, error) {
	var resp *logical.Response
	warnings, err := role.validate(b.System())

	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}
	if len(warnings) > 0 {
		resp = &logical.Response{
			Warnings: warnings,
		}
	}

	entry, err := logical.StorageEntryJSON(fmt.Sprintf("role/%s", roleName), role)
	if err != nil {
		return nil, err
	}

	if err := s.Put(entry); err != nil {
		return nil, err
	}

	return resp, nil
}

type role struct {
	// Policies for Vault to assign to authorized entities.
	Policies []string `json:"policies" structs:"policies" mapstructure:"policies"`

	// Domain for authorized entities.
	BoundDomain string `json:"domain" structs:"domain" mapstructure:"domain"`

	// BoundGroups that instances must belong to in order to login under this role.
	BoundGroups []string `json:"bound_groups" structs:"bound_groups" mapstructure:"bound_groups"`

	// TTL of Vault auth leases under this role.
	TTL time.Duration `json:"ttl" structs:"ttl" mapstructure:"ttl"`

	// Max total TTL including renewals, of Vault auth leases under this role.
	MaxTTL time.Duration `json:"max_ttl" structs:"max_ttl" mapstructure:"max_ttl"`

	// Period, If set, indicates that this token should not expire and
	// should be automatically renewed within this time period
	// with TTL equal to this value.
	Period time.Duration `json:"period" structs:"period" mapstructure:"period"`
}

// Update updates the given role with values parsed/validated from given FieldData.
// Exactly one of the response and error will be nil. The response is only used to pass back warnings.
// This method does not validate the role. Validation is done before storage.
func (role *role) updateRole(sys logical.SystemView, op logical.Operation, data *framework.FieldData) error {
	// Update policies.
	policies, ok := data.GetOk("policies")
	if ok {
		role.Policies = policyutil.ParsePolicies(policies)
	} else if op == logical.CreateOperation {
		role.Policies = policyutil.ParsePolicies(data.Get("policies"))
	}

	// Update bound domain.
	boundDomainRaw, ok := data.GetOk("bound_domain")
	if ok {
		role.BoundDomain = boundDomainRaw.(string)
	}

	// Update bound groups.
	boundGroupsRaw, ok := data.GetOk("bound_groups")
	if ok {
		role.BoundGroups = boundGroupsRaw.([]string)
	}

	// Update token TTL.
	ttlRaw, ok := data.GetOk("ttl")
	if ok {
		role.TTL = time.Duration(ttlRaw.(int)) * time.Second

	} else if op == logical.CreateOperation {
		role.TTL = time.Duration(data.Get("ttl").(int)) * time.Second
	}

	// Update token Max TTL.
	maxTTLRaw, ok := data.GetOk("max_ttl")
	if ok {
		role.MaxTTL = time.Duration(maxTTLRaw.(int)) * time.Second
	} else if op == logical.CreateOperation {
		role.MaxTTL = time.Duration(data.Get("max_ttl").(int)) * time.Second
	}

	// Update token period.
	periodRaw, ok := data.GetOk("period")
	if ok {
		role.Period = time.Second * time.Duration(periodRaw.(int))
	} else if op == logical.CreateOperation {
		role.Period = time.Second * time.Duration(data.Get("period").(int))
	}

	return nil
}

func (role *role) validate(sys logical.SystemView) (warnings []string, err error) {
	warnings = []string{}

	if role.BoundDomain == "" {
		return warnings, errors.New(errEmptyDomain)
	}

	defaultLeaseTTL := sys.DefaultLeaseTTL()
	if role.TTL > defaultLeaseTTL {
		warnings = append(warnings, fmt.Sprintf(
			"Given ttl of %d seconds greater than current mount/system default of %d seconds; ttl will be capped at login time",
			role.TTL/time.Second, defaultLeaseTTL/time.Second))
	}

	defaultMaxTTL := sys.MaxLeaseTTL()
	if role.MaxTTL > defaultMaxTTL {
		warnings = append(warnings, fmt.Sprintf(
			"Given max_ttl of %d seconds greater than current mount/system default of %d seconds; max_ttl will be capped at login time",
			role.MaxTTL/time.Second, defaultMaxTTL/time.Second))
	}
	if role.MaxTTL < time.Duration(0) {
		return warnings, errors.New("max_ttl cannot be negative")
	}
	if role.MaxTTL != 0 && role.MaxTTL < role.TTL {
		return warnings, errors.New("ttl should be shorter than max_ttl")
	}

	if role.Period > sys.MaxLeaseTTL() {
		return warnings, fmt.Errorf("'period' of '%s' is greater than the backend's maximum lease TTL of '%s'", role.Period.String(), sys.MaxLeaseTTL().String())
	}

	return warnings, nil
}
