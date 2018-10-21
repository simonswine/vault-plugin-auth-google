package google

import (
	"context"
	"fmt"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/golang/mock/gomock"
	"github.com/hashicorp/vault/logical"
	logicaltest "github.com/hashicorp/vault/logical/testing"
	"golang.org/x/oauth2"
	"google.golang.org/api/admin/directory/v1"
	goauth "google.golang.org/api/oauth2/v2"
)

type expectFunc func(*logical.Response) error

func newTestBackend() (*backend, error) {
	defaultLeaseTTLVal := time.Hour * 24
	maxLeaseTTLVal := time.Hour * 24 * 32
	b, err := Factory(context.Background(), &logical.BackendConfig{
		Logger: nil,
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLeaseTTLVal,
			MaxLeaseTTLVal:     maxLeaseTTLVal,
		},
	})

	return b.(*backend), err
}

func newTestBackendMocked(t *testing.T) (*gomock.Controller, *MockUserProvider, *MockGroupsProvider, *backend) {
	b, err := newTestBackend()
	if err != nil {
		t.Fatalf("Unable to create backend: %s", err)
	}

	ctrl := gomock.NewController(t)

	userMock := NewMockUserProvider(ctrl)
	groupsMock := NewMockGroupsProvider(ctrl)
	b.user = userMock
	b.groups = groupsMock

	return ctrl, userMock, groupsMock, b
}

// test if we get errors and/or code URL based on endpoint
func TestBackend_CodeURL(t *testing.T) {
	b, err := newTestBackend()
	if err != nil {
		t.Fatalf("Unable to create backend: %s", err)
	}

	noConfigData := map[string]interface{}{
		cliClientIDConfigPropertyName:     "",
		cliClientSecretConfigPropertyName: "",
		webClientIDConfigPropertyName:     "",
		webClientSecretConfigPropertyName: "",
		webRedirectURLConfigPropertyName:  "",
	}

	cliMissing := testCodeURLRead(t, cliCodeURLPath, true, expectFailWithError("missing config for CLI oauth2 client"))
	webMissing := testCodeURLRead(t, webCodeURLPath, true, expectFailWithError("missing config for web oauth2 client"))

	cliConfigData := map[string]interface{}{
		cliClientIDConfigPropertyName:     "cli-id",
		cliClientSecretConfigPropertyName: "cli-secret",
		webClientIDConfigPropertyName:     "",
		webClientSecretConfigPropertyName: "",
		webRedirectURLConfigPropertyName:  "",
	}

	cliFine := testCodeURLRead(t, cliCodeURLPath, false, func(resp *logical.Response) error {
		u, err := url.Parse(resp.Data["url"].(string))
		if err != nil {
			t.Errorf("failed to parse url: %s", err)
		}

		stateData := resp.Data["state"].(string)
		stateURL := u.Query().Get("state")

		if len(stateData) == 0 {
			t.Errorf("state in data is empty")
		}

		if len(stateURL) == 0 {
			t.Errorf("state in URL is empty")
		}

		if exp, act := stateURL, stateData; exp != act {
			t.Errorf("state mismatches: url=%s data=%s", exp, act)
		}

		if exp, act := "cli-id", u.Query().Get("client_id"); exp != act {
			t.Errorf("unexpected client id in url: exp=%s act=%s", exp, act)
		}
		if exp, act := "urn:ietf:wg:oauth:2.0:oob", u.Query().Get("redirect_uri"); exp != act {
			t.Errorf("unexpected redirect uri in url: exp=%s act=%s", exp, act)
		}
		return nil
	})

	webConfigData := map[string]interface{}{
		cliClientIDConfigPropertyName:     "",
		cliClientSecretConfigPropertyName: "",
		webClientIDConfigPropertyName:     "web-id",
		webClientSecretConfigPropertyName: "web-secret",
		webRedirectURLConfigPropertyName:  "https://thefuck.com/callback",
	}

	webFine := testCodeURLRead(t, webCodeURLPath, false, func(resp *logical.Response) error {
		u, err := url.Parse(resp.Data["url"].(string))
		if err != nil {
			t.Errorf("failed to parse url: %s", err)
		}

		stateData := resp.Data["state"].(string)
		stateURL := u.Query().Get("state")

		if len(stateData) == 0 {
			t.Errorf("state in data is empty")
		}

		if len(stateURL) == 0 {
			t.Errorf("state in URL is empty")
		}

		if exp, act := stateURL, stateData; exp != act {
			t.Errorf("state mismatches: url=%s data=%s", exp, act)
		}

		if exp, act := "web-id", u.Query().Get("client_id"); exp != act {
			t.Errorf("unexpected client id in url: exp=%s act=%s", exp, act)
		}
		if exp, act := "https://thefuck.com/callback/ui/vault/auth/google/callback/google", u.Query().Get("redirect_uri"); exp != act {
			t.Errorf("unexpected redirect uri in url: exp=%s act=%s", exp, act)
		}
		return nil
	})

	bothConfigData := map[string]interface{}{
		cliClientIDConfigPropertyName:     "cli-id",
		cliClientSecretConfigPropertyName: "cli-secret",
		webClientIDConfigPropertyName:     "web-id",
		webClientSecretConfigPropertyName: "web-secret",
		webRedirectURLConfigPropertyName:  "https://thefuck.com/callback",
	}

	logicaltest.Test(t, logicaltest.TestCase{
		Backend: b,
		Steps: []logicaltest.TestStep{
			testConfigWrite(t, noConfigData),
			cliMissing,
			webMissing,
			testConfigWrite(t, cliConfigData),
			cliFine,
			webMissing,
			testConfigWrite(t, webConfigData),
			cliMissing,
			webFine,
			testConfigWrite(t, bothConfigData),
			cliFine,
			webFine,
		},
	})
}

func expectFailWithError(subString string) expectFunc {
	return func(resp *logical.Response) error {
		if !resp.IsError() {
			return fmt.Errorf("error was expected")
		}
		if !strings.Contains(resp.Error().Error(), subString) {
			return fmt.Errorf("an error that contains '%s' was expected, got '%s'", subString, resp.Error().Error())
		}
		return nil
	}
}

func testCodeURLRead(t *testing.T, path string, fail bool, expects ...expectFunc) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ReadOperation,
		Path:      path,
		ErrorOk:   fail,
		Check: func(resp *logical.Response) error {
			for _, f := range expects {
				if err := f(resp); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

func testConfigWrite(t *testing.T, d map[string]interface{}) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.UpdateOperation,
		Path:      "config",
		Data:      d,
	}
}

func testConfigRead(t *testing.T, expects ...expectFunc) logicaltest.TestStep {
	return logicaltest.TestStep{
		Operation: logical.ReadOperation,
		Path:      "config",
		Check: func(resp *logical.Response) error {
			for _, f := range expects {
				if err := f(resp); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

// test the full login flow
func TestBackend_Login(t *testing.T) {
	ctrl, userMock, groupsMock, b := newTestBackendMocked(t)
	defer ctrl.Finish()

	configData := map[string]interface{}{
		cliTTLConfigPropertyName:          "33m",
		cliMaxTTLConfigPropertyName:       "44m",
		cliClientIDConfigPropertyName:     "cli-id",
		cliClientSecretConfigPropertyName: "cli-secret",
		webTTLConfigPropertyName:          "11m",
		webMaxTTLConfigPropertyName:       "22m",
		webClientIDConfigPropertyName:     "web-id",
		webClientSecretConfigPropertyName: "web-secret",
		webRedirectURLConfigPropertyName:  "https://thefuck.com/callback",
	}

	checkConfigRead := testConfigRead(
		t,
		func(r *logical.Response) error {
			for _, d := range []struct {
				key   string
				value time.Duration
			}{
				{cliTTLConfigPropertyName, time.Duration(33) * time.Minute},
				{cliMaxTTLConfigPropertyName, time.Duration(44) * time.Minute},
				{webTTLConfigPropertyName, time.Duration(11) * time.Minute},
				{webMaxTTLConfigPropertyName, time.Duration(22) * time.Minute},
			} {
				if exp, act := d.value.String(), r.Data[d.key].(string); exp != act {
					t.Errorf("Unexecected value for %s: exp=%s act=%s", d.key, exp, act)
				}
			}
			return nil
		},
	)

	webToken := &oauth2.Token{AccessToken: "my-web-access-token", RefreshToken: "my-web-refresh-token"}
	webClientIDMatcher := &oauth2ConfigClientIDMatcher{clientID: "web-id", t: t}
	webUser := &goauth.Userinfoplus{
		Email:      "me-web@my.com",
		Hd:         "my.com",
		FamilyName: "Webber",
		GivenName:  "Web M.",
	}
	webGroups := []*admin.Group{
		&admin.Group{
			Name:  "Group with both",
			Email: "both@my.com",
		},
		&admin.Group{
			Name:  "Web only",
			Email: "web@my.com",
		},
	}

	userMock.EXPECT().oauth2Exchange(gomock.Any(), gomock.Eq("my-web-code"), webClientIDMatcher).Times(1).Return(webToken, nil)
	userMock.EXPECT().authUser(gomock.Any(), gomock.Any(), gomock.Eq(webToken)).Times(1).Return(webUser, nil)
	groupsMock.EXPECT().groupsPerUser(gomock.Any(), gomock.Any(), gomock.Eq("me-web@my.com")).Times(1).Return(webGroups, nil)

	var webState = &struct{ State string }{}
	webStateAndURL := testCodeURLRead(t, webCodeURLPath, false, func(resp *logical.Response) error {
		webState.State = resp.Data[stateParameterName].(string)

		return nil
	})

	webLogin := testLoginWrite(
		t,
		map[string]interface{}{
			googleAuthCodeParameterName: "my-web-code",
		},
		webState,
		false,
	)
	webLoginFailSecondTime := testLoginWrite(
		t,
		map[string]interface{}{
			googleAuthCodeParameterName: "my-web-code",
		},
		webState,
		true,
		expectFailWithError("this state can't be found or has already been used"),
	)

	cliToken := &oauth2.Token{AccessToken: "my-cli-access-token", RefreshToken: "my-cli-refresh-token"}
	cliTokenNoState := &oauth2.Token{AccessToken: "my-cli-access-token-nostate", RefreshToken: "my-cli-refresh-token-nostate"}
	cliClientIDMatcher := &oauth2ConfigClientIDMatcher{clientID: "cli-id", t: t}
	cliUser := &goauth.Userinfoplus{
		Email:      "me-cli@my.com",
		Hd:         "my.com",
		FamilyName: "Clier",
		GivenName:  "Cli M.",
	}
	cliGroups := []*admin.Group{
		&admin.Group{
			Name:  "Group with both",
			Email: "both@my.com",
		},
		&admin.Group{
			Name:  "CLI only",
			Email: "cli@my.com",
		},
	}

	userMock.EXPECT().oauth2Exchange(gomock.Any(), gomock.Eq("my-cli-code"), cliClientIDMatcher).Times(1).Return(cliToken, nil)
	userMock.EXPECT().authUser(gomock.Any(), gomock.Any(), gomock.Eq(cliToken)).Times(1).Return(cliUser, nil)
	userMock.EXPECT().oauth2Exchange(gomock.Any(), gomock.Eq("my-cli-code-nostate"), cliClientIDMatcher).Times(1).Return(cliTokenNoState, nil)
	userMock.EXPECT().authUser(gomock.Any(), gomock.Any(), gomock.Eq(cliTokenNoState)).Times(1).Return(cliUser, nil)
	groupsMock.EXPECT().groupsPerUser(gomock.Any(), gomock.Any(), gomock.Eq("me-cli@my.com")).Times(2).Return(cliGroups, nil)

	var cliState = &struct{ State string }{}
	cliFine := testCodeURLRead(t, cliCodeURLPath, false, func(resp *logical.Response) error {
		cliState.State = resp.Data["state"].(string)
		return nil
	})

	cliLogin := testLoginWrite(
		t,
		map[string]interface{}{
			googleAuthCodeParameterName: "my-cli-code",
		},
		cliState,
		false,
	)
	cliLoginFailSecondTime := testLoginWrite(
		t,
		map[string]interface{}{
			googleAuthCodeParameterName: "my-cli-code",
		},
		cliState,
		true,
		expectFailWithError("this state can't be found or has already been used"),
	)
	cliLoginNoState := testLoginWrite(
		t,
		map[string]interface{}{
			googleAuthCodeParameterName: "my-cli-code-nostate",
		},
		nil,
		false,
	)

	logicaltest.Test(t, logicaltest.TestCase{
		Backend: b,
		Steps: []logicaltest.TestStep{
			testConfigWrite(t, configData),
			checkConfigRead,
			// test Web
			webStateAndURL,
			webLogin,
			webLoginFailSecondTime,
			// test cli now
			cliFine,
			cliLogin,
			cliLoginFailSecondTime,
			cliLoginNoState,
		},
	})

}

// tests the group, user, domain authorisation as part of the login
func TestBackend_LoginAuthorisation(t *testing.T) {
	ctrl, userMock, groupsMock, b := newTestBackendMocked(t)
	defer ctrl.Finish()

	groupA := &admin.Group{
		Name:  "Group A",
		Email: "group-a@a.com",
	}
	groupAB := &admin.Group{
		Name:  "Group AB",
		Email: "group-ab@a.com",
	}
	groupABC := &admin.Group{
		Name:    "Group ABC",
		Email:   "group-abc@a.com",
		Aliases: []string{"team-abc@a.com"},
	}

	userA := &goauth.Userinfoplus{
		Email: "a@a.com",
		Hd:    "a.com",
	}
	userB := &goauth.Userinfoplus{
		Email: "b@b.com",
		Hd:    "b.com",
	}
	userC := &goauth.Userinfoplus{
		Email: "c@b.com",
		Hd:    "b.com",
	}

	userMock.EXPECT().oauth2Exchange(gomock.Any(), gomock.Eq(userA.Email), gomock.Any()).AnyTimes().Return(&oauth2.Token{AccessToken: userA.Email}, nil)
	userMock.EXPECT().oauth2Exchange(gomock.Any(), gomock.Eq(userB.Email), gomock.Any()).AnyTimes().Return(&oauth2.Token{AccessToken: userB.Email}, nil)
	userMock.EXPECT().oauth2Exchange(gomock.Any(), gomock.Eq(userC.Email), gomock.Any()).AnyTimes().Return(&oauth2.Token{AccessToken: userC.Email}, nil)
	userMock.EXPECT().authUser(gomock.Any(), gomock.Any(), gomock.Eq(&oauth2.Token{AccessToken: userA.Email})).AnyTimes().Return(userA, nil)
	userMock.EXPECT().authUser(gomock.Any(), gomock.Any(), gomock.Eq(&oauth2.Token{AccessToken: userB.Email})).AnyTimes().Return(userB, nil)
	userMock.EXPECT().authUser(gomock.Any(), gomock.Any(), gomock.Eq(&oauth2.Token{AccessToken: userC.Email})).AnyTimes().Return(userC, nil)

	groupsUserA := []*admin.Group{groupA, groupAB, groupABC}
	groupsUserB := []*admin.Group{groupAB, groupABC}
	groupsUserC := []*admin.Group{groupABC}
	groupsMock.EXPECT().groupsPerUser(gomock.Any(), gomock.Any(), gomock.Eq(userA.Email)).AnyTimes().Return(groupsUserA, nil)
	groupsMock.EXPECT().groupsPerUser(gomock.Any(), gomock.Any(), gomock.Eq(userB.Email)).AnyTimes().Return(groupsUserB, nil)
	groupsMock.EXPECT().groupsPerUser(gomock.Any(), gomock.Any(), gomock.Eq(userC.Email)).AnyTimes().Return(groupsUserC, nil)

	loginUser := func(u *goauth.Userinfoplus, success bool) logicaltest.TestStep {
		var checks []expectFunc

		if !success {
			checks = append(checks, expectFailWithError("user is not allowed to login"))
		}

		return testLoginWrite(
			t,
			map[string]interface{}{
				"code": u.Email,
			},
			nil,
			!success,
			checks...,
		)
	}

	configData := map[string]interface{}{
		cliClientIDConfigPropertyName:                "cli-id",
		cliClientSecretConfigPropertyName:            "cli-secret",
		directoryImpersonateUserConfigPropertyName:   "myadmin@user.com",
		directoryServiceAccountKeyConfigPropertyName: "secret",
	}

	logicaltest.Test(t, logicaltest.TestCase{
		Backend: b,
		Steps: []logicaltest.TestStep{
			// test defaults, every one allowed
			testConfigWrite(t, configData),
			loginUser(userA, true),
			loginUser(userB, true),
			loginUser(userC, true),
			// no one is allowed
			testConfigWrite(t, map[string]interface{}{
				allowedUsersConfigPropertyName:   "user-not@existing.net",
				allowedDomainsConfigPropertyName: "",
				allowedGroupsConfigPropertyName:  "",
			}),
			loginUser(userA, false),
			loginUser(userB, false),
			loginUser(userC, false),
			testConfigWrite(t, map[string]interface{}{
				allowedUsersConfigPropertyName:   userC.Email,
				allowedDomainsConfigPropertyName: userA.Hd,
				allowedGroupsConfigPropertyName:  "",
			}),
			loginUser(userA, true),
			loginUser(userB, false),
			loginUser(userC, true),
			testConfigWrite(t, map[string]interface{}{
				allowedUsersConfigPropertyName:   "",
				allowedDomainsConfigPropertyName: "",
				allowedGroupsConfigPropertyName:  strings.Join([]string{groupA.Email, groupAB.Email}, ","),
			}),
			loginUser(userA, true),
			loginUser(userB, true),
			loginUser(userC, false),
			testConfigWrite(t, map[string]interface{}{
				allowedUsersConfigPropertyName:   "",
				allowedDomainsConfigPropertyName: "",
				allowedGroupsConfigPropertyName:  groupABC.Aliases[0],
			}),
			loginUser(userA, true),
			loginUser(userB, true),
			loginUser(userC, true),
		},
	})
}

type oauth2ConfigClientIDMatcher struct {
	t        *testing.T
	clientID string
}

func (o *oauth2ConfigClientIDMatcher) Matches(obj interface{}) bool {
	c := obj.(*oauth2.Config)
	if c == nil {
		o.t.Logf("no oauth2 config found")
		return false
	}
	if c.ClientID != o.clientID {
		o.t.Logf("unexpected client ID exp=%s act=%s", o.clientID, c.ClientID)
		return false
	}
	return true
}

func (o *oauth2ConfigClientIDMatcher) String() string {
	return fmt.Sprintf("Check if client ID matches '%s'", o.clientID)
}

func testLoginWrite(t *testing.T, d map[string]interface{}, state *struct{ State string }, fail bool, expects ...expectFunc) logicaltest.TestStep {
	return logicaltest.TestStep{
		PreFlight: func(r *logical.Request) error {
			if state != nil {
				r.Data[stateParameterName] = state.State
			}
			return nil
		},
		Operation: logical.UpdateOperation,
		Path:      "login",
		Data:      d,
		ErrorOk:   fail,
		Check: func(resp *logical.Response) error {
			for _, f := range expects {
				if err := f(resp); err != nil {
					return err
				}
			}
			return nil
		},
	}
}
