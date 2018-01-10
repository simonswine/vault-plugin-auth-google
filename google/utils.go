package google

import (
	"encoding/json"
	"net/mail"
	"strings"

	"golang.org/x/oauth2"
)

//copied from vault/util... make public?
func strListContains(haystack []string, needle string) bool {
	for _, item := range haystack {
		if item == needle {
			return true
		}
	}
	return false
}

func sliceToMap(slice []string) map[string]bool {
	m := map[string]bool{}
	for _, element := range slice {
		m[element] = true
	}
	return m
}

func localPartFromEmail(email string) (string, error) {
	address, err := mail.ParseAddress(email)
	if err != nil {
		return "", err
	}

	var name string
	if index := strings.Index(address.Address, "@"); index > -1 {
		name = address.Address[:index]
	} else {
		name = address.Address
	}
	return name, nil
}

func encodeToken(token *oauth2.Token) (string, error) {
	buf, err := json.Marshal(token)
	if err != nil {
		return "", err
	}
	return string(buf), err
}

func decodeToken(encoded string) (*oauth2.Token, error) {
	var token oauth2.Token
	if err := json.Unmarshal([]byte(encoded), &token); err != nil {
		return nil, err
	}
	return &token, nil
}
