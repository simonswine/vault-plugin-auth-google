package google

import (
	"context"
	"errors"
	"fmt"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/admin/directory/v1"
	goauth "google.golang.org/api/oauth2/v2"
)

type googleProvider struct {
}

// UserProvider does the authentication of user with oauth2
type UserProvider interface {
	authUser(ctx context.Context, config *oauth2.Config, token *oauth2.Token) (*goauth.Userinfoplus, error)
	oauth2Exchange(ctx context.Context, code string, config *oauth2.Config) (*oauth2.Token, error)
}

// GroupsProvider maps a user to its groups
type GroupsProvider interface {
	groupsPerUser(ctx context.Context, config *config, userKey string) ([]*admin.Group, error)
}

var _ UserProvider = &googleProvider{}
var _ GroupsProvider = &googleProvider{}

func (p *googleProvider) oauth2Exchange(ctx context.Context, code string, config *oauth2.Config) (*oauth2.Token, error) {
	return config.Exchange(ctx, code)
}

func (p *googleProvider) authUser(ctx context.Context, config *oauth2.Config, token *oauth2.Token) (*goauth.Userinfoplus, error) {
	client := config.Client(ctx, token)
	userService, err := goauth.New(client)
	if err != nil {
		return nil, err
	}

	user, err := goauth.NewUserinfoV2MeService(userService).Get().Do()
	if err != nil {
		return nil, err
	}

	return user, nil
}

func (p *googleProvider) directoryService(ctx context.Context, config *config) (*admin.Service, error) {
	if config == nil {
		return nil, errors.New("missing config")
	}
	// TODO: Handle unconfigured service account

	jwtConfig, err := google.JWTConfigFromJSON([]byte(config.DirectoryServiceAccounyKey), admin.AdminDirectoryUserReadonlyScope, admin.AdminDirectoryGroupReadonlyScope)
	if err != nil {
		return nil, err
	}
	jwtConfig.Subject = config.DirectoryImpersonateUser

	client := jwtConfig.Client(ctx)

	srv, err := admin.New(client)
	if err != nil {
		return nil, fmt.Errorf("Unable to create directory service %v", err)
	}
	return srv, nil
}

func (p *googleProvider) groupsPerUser(ctx context.Context, config *config, userKey string) (groups []*admin.Group, err error) {
	// skip groups check if service account is not configured
	if len(config.DirectoryImpersonateUser) == 0 || len(config.DirectoryServiceAccounyKey) == 0 {
		return []*admin.Group{}, nil
	}

	svc, err := p.directoryService(ctx, config)
	if err != nil {
		return []*admin.Group{}, err
	}

	query := svc.Groups.List().UserKey(userKey)

	for {
		resp, err := query.Do()
		if err != nil {
			return []*admin.Group{}, err
		}
		groups = append(groups, resp.Groups...)

		if resp.NextPageToken == "" {
			break
		}
		query.PageToken(resp.NextPageToken)
	}

	return groups, nil
}
