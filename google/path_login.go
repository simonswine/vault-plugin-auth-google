package google

import (
	"errors"
	"fmt"
	"reflect"
	"sort"
	"time"

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

	verifyResp, resp, err := b.verifyCredentials(req, code, nil)
	if err != nil {
		return nil, err
	} else if resp != nil {
		return resp, nil
	}

	config, err := b.config(req.Storage)
	if err != nil {
		return nil, err
	}

	ttl, _, err := b.SanitizeTTL(config.TTL, config.MaxTTL)
	if err != nil {
		return nil, err
	}

	internalData := map[string]interface{}{
		refreshToken: verifyResp.RefreshToken,
	}

	return &logical.Response{
		Auth: &logical.Auth{
			InternalData: internalData,
			Policies:     verifyResp.Policies,
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

func (b *backend) pathLoginRenew(req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	previousTokenObject := req.Auth.InternalData[refreshToken]
	if previousTokenObject == nil {
		return nil, errors.New("no refresh token from previous login")
	}
	previousTokenMap := previousTokenObject.(map[string]interface{})
	expiryString := previousTokenMap["expiry"].(string)
	expiry, err := time.Parse(time.RFC3339Nano, expiryString)
	if err != nil {
		return nil, fmt.Errorf("could not parse time (%s) from persisted token", expiryString)
	}
	refreshToken := &oauth2.Token{
		AccessToken:  previousTokenMap["access_token"].(string),
		TokenType:    previousTokenMap["token_type"].(string),
		RefreshToken: previousTokenMap["refresh_token"].(string),
		Expiry:       expiry,
	}

	verifyResp, resp, err := b.verifyCredentials(req, "", refreshToken)
	if err != nil {
		return nil, err
	} else if resp != nil {
		return resp, nil
	}

	sort.Strings(req.Auth.Policies)
	if !reflect.DeepEqual(sliceToMap(verifyResp.Policies), sliceToMap(req.Auth.Policies)) {
		return logical.ErrorResponse(fmt.Sprintf("policies do not match. new policies: %s. old policies: %s.", verifyResp.Policies, req.Auth.Policies)), nil
	}

	config, err := b.config(req.Storage)
	if err != nil {
		return nil, err
	}
	return framework.LeaseExtend(config.TTL, config.MaxTTL, b.System())(req, d)
}

func (b *backend) verifyCredentials(req *logical.Request, code string, tok *oauth2.Token) (*verifyCredentialsResp, *logical.Response, error) {
	config, err := b.config(req.Storage)
	if err != nil {
		return nil, nil, err
	}

	googleConfig := config.oauth2Config()
	if tok == nil && code != "" {
		tok, err = googleConfig.Exchange(oauth2.NoContext, code)
		if err != nil {
			return nil, nil, err
		}
	}

	httpClient := googleConfig.Client(context.Background(), tok)
	service, err := goauth.New(httpClient)
	if err != nil {
		return nil, nil, err
	}

	me := goauth.NewUserinfoV2MeService(service)
	info, err := me.Get().Do()
	if err != nil {
		return nil, nil, err
	}

	user := info.Email
	domain := info.Hd

	if domain != config.Domain {
		return nil, logical.ErrorResponse(fmt.Sprintf("user %s is of domain %s, not part of required domain %s", user, domain, config.Domain)), nil
	}

	userID := localPartFromEmail(user)
	policiesList, err := b.Map.Policies(req.Storage, userID)
	//be compatible with core, see issue https://github.com/hashicorp/vault/issues/1256
	if strListContains(policiesList, "root") {
		policiesList = []string{"root"}
	} else {
		policiesList = append(policiesList, "default")
	}

	if err != nil {
		return nil, nil, err
	}
	return &verifyCredentialsResp{
		User:         user,
		Domain:       domain,
		Policies:     policiesList,
		RefreshToken: tok,
		Name:         info.Name,
	}, nil, nil
}

type verifyCredentialsResp struct {
	User         string
	Domain       string
	Name         string
	Policies     []string
	RefreshToken *oauth2.Token
}
