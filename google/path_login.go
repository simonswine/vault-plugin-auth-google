package google

import (
	"errors"
	"fmt"
	"reflect"
	"sort"

	"golang.org/x/net/context"
	"golang.org/x/oauth2"
	goauth "google.golang.org/api/oauth2/v2"

	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

const (
	loginPath                   = "login"
	googleAuthCodeParameterName = "code"
	refreshToken                = "refreshToken"
)

func (b *backend) pathLogin(req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	code := data.Get(googleAuthCodeParameterName).(string)

	config, err := b.config(req.Storage)
	if err != nil {
		return nil, err
	}

	verifyResp, err := b.verifyCredentials(config, code, nil)
	if err != nil {
		return nil, err
	}

	ttl, _, err := b.SanitizeTTL(config.TTL, config.MaxTTL)
	if err != nil {
		return nil, err
	}

	encoded, err := encodeToken(verifyResp.RefreshToken)
	if err != nil {
		return nil, err
	}

	return &logical.Response{
		Auth: &logical.Auth{
			InternalData: map[string]interface{}{
				refreshToken: encoded,
			},
			Policies: verifyResp.Policies,
			Metadata: map[string]string{
				"username": verifyResp.User,
				"domain":   verifyResp.Domain,
			},
			DisplayName: verifyResp.Name,
			LeaseOptions: logical.LeaseOptions{
				TTL:       ttl,
				Renewable: true,
			},
		},
	}, nil
}

func (b *backend) authRenew(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	previousToken, ok := req.Auth.InternalData[refreshToken].(string)
	if !ok {
		return nil, errors.New("no refresh token from previous login")
	}

	refreshToken, err := decodeToken(previousToken)
	if err != nil {
		return nil, err
	}

	config, err := b.config(req.Storage)
	if err != nil {
		return nil, err
	}

	verifyResp, err := b.verifyCredentials(config, "", refreshToken)
	if err != nil {
		return nil, err
	}

	sort.Strings(req.Auth.Policies)
	if !reflect.DeepEqual(sliceToMap(verifyResp.Policies), sliceToMap(req.Auth.Policies)) {
		return logical.ErrorResponse(fmt.Sprintf("policies do not match. new policies: %s. old policies: %s.", verifyResp.Policies, req.Auth.Policies)), nil
	}

	ttl, maxTTL, err := b.SanitizeTTL(config.TTL, config.MaxTTL)
	if err != nil {
		return nil, err
	}

	return framework.LeaseExtend(ttl, maxTTL, b.System())(req, d)
}

func (b *backend) verifyCredentials(config *config, code string, tok *oauth2.Token) (*verifyCredentialsResp, error) {
	googleConfig := config.oauth2Config()
	if tok == nil && code != "" {
		var err error
		tok, err = googleConfig.Exchange(oauth2.NoContext, code)
		if err != nil {
			return nil, err
		}
	}

	httpClient := googleConfig.Client(context.Background(), tok)
	service, err := goauth.New(httpClient)
	if err != nil {
		return nil, err
	}

	me := goauth.NewUserinfoV2MeService(service)
	info, err := me.Get().Do()
	if err != nil {
		return nil, err
	}

	domain := info.Hd
	if domain != config.Domain {
		return nil, fmt.Errorf("user is of domain %s, not part of required domain %s", domain, config.Domain)
	}

	userID, err := localPartFromEmail(info.Email)
	if err != nil {
		return nil, err
	}

	return &verifyCredentialsResp{
		User:         userID,
		Domain:       domain,
		Policies:     []string{},
		RefreshToken: tok,
		Name:         info.Name,
	}, nil
}

type verifyCredentialsResp struct {
	User         string
	Domain       string
	Name         string
	Policies     []string
	RefreshToken *oauth2.Token
}
