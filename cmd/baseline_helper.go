package cmd

import (
	"strings"
)

func (s *Scanner) urlContainsParams(urlStr string, params map[string]string) bool {
	if len(params) == 0 {
		return false
	}
	for _, val := range params {
		if val != "" && strings.Contains(urlStr, val) {
			return true
		}
	}
	return false
}