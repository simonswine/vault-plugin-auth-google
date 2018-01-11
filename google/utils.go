package google

import (
	"encoding/json"
	"sort"

	"golang.org/x/oauth2"
)

func strSliceEquals(a, b []string) bool {
	sort.Strings(a)
	sort.Strings(b)
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func strSliceHasIntersection(a, b []string) bool {
	sort.Strings(a)
	sort.Strings(b)
	for i, j := 0, 0; i < len(a) && j < len(b); {
		if a[i] == b[j] {
			return true
		}
		if a[i] < b[j] {
			i++
		} else {
			j++
		}
	}
	return false
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
