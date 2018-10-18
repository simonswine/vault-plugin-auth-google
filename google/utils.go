package google

import (
	"encoding/json"

	"golang.org/x/oauth2"
)

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
