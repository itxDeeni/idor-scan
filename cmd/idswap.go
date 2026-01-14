package cmd

import (
	"regexp"
	"strings"
)

// IDPattern represents a detected ID pattern in a URL or body
type IDPattern struct {
	Location string // "path", "query", "body"
	Key      string // parameter name or path segment index
	Value    string // the actual ID value
}

// Common ID patterns
var idPatterns = []*regexp.Regexp{
	regexp.MustCompile(`[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`), // UUID
	regexp.MustCompile(`[0-9a-f]{24}`),                                                   // MongoDB ObjectId
	regexp.MustCompile(`\b\d{1,10}\b`),                                                   // Numeric ID (1-10 digits)
}

// Path segments that typically contain IDs
var idSegmentPatterns = []string{
	"users", "user", "accounts", "account", "profiles", "profile",
	"orders", "order", "items", "item", "posts", "post",
	"comments", "comment", "messages", "message", "files", "file",
	"documents", "document", "records", "record", "entries", "entry",
	"customers", "customer", "products", "product", "invoices", "invoice",
}

// ExtractIDsFromURL finds potential ID values in a URL path
func ExtractIDsFromURL(urlStr string) []IDPattern {
	patterns := []IDPattern{}

	// Parse path segments
	parts := strings.Split(urlStr, "/")
	for i, part := range parts {
		if part == "" {
			continue
		}

		// Check if previous segment suggests this is an ID
		if i > 0 {
			prevPart := strings.ToLower(parts[i-1])
			for _, seg := range idSegmentPatterns {
				if prevPart == seg || strings.HasSuffix(prevPart, seg) {
					// This segment likely contains an ID
					for _, re := range idPatterns {
						if re.MatchString(part) {
							patterns = append(patterns, IDPattern{
								Location: "path",
								Key:      prevPart,
								Value:    part,
							})
							break
						}
					}
					break
				}
			}
		}

		// Also check for placeholder patterns that weren't replaced
		if strings.HasPrefix(part, "{") && strings.HasSuffix(part, "}") {
			patterns = append(patterns, IDPattern{
				Location: "path",
				Key:      strings.Trim(part, "{}"),
				Value:    part,
			})
		}
	}

	return patterns
}

// SwapIDsInURL replaces IDs in the URL with values from the target user
func SwapIDsInURL(urlStr string, sourceIDs []IDPattern, targetParams map[string]string) string {
	result := urlStr

	for _, id := range sourceIDs {
		// Try to find a matching param in target
		for paramKey, paramVal := range targetParams {
			// Match by key name
			if strings.Contains(strings.ToLower(paramKey), strings.ToLower(id.Key)) ||
				strings.Contains(strings.ToLower(id.Key), strings.ToLower(paramKey)) {
				result = strings.ReplaceAll(result, id.Value, paramVal)
				break
			}
		}
	}

	return result
}

// BuildSwappedURL creates a URL with the victim's IDs using the attacker's perspective
func BuildSwappedURL(originalURL string, attackerParams, victimParams map[string]string) string {
	result := originalURL

	// Strategy 1: Replace placeholders (existing logic)
	for key, val := range victimParams {
		placeholders := []string{
			"{" + key + "}",
			":" + key,
			"{{" + key + "}}",
		}
		for _, placeholder := range placeholders {
			result = strings.ReplaceAll(result, placeholder, val)
		}
	}

	// Strategy 2: Replace attacker's hardcoded IDs with victim's IDs
	// This handles cases where the URL already has the attacker's ID baked in
	for key, attackerVal := range attackerParams {
		if victimVal, ok := victimParams[key]; ok && attackerVal != victimVal {
			// Replace attacker's ID with victim's ID
			result = strings.ReplaceAll(result, "/"+attackerVal+"/", "/"+victimVal+"/")
			result = strings.ReplaceAll(result, "/"+attackerVal+"?", "/"+victimVal+"?")
			if strings.HasSuffix(result, "/"+attackerVal) {
				result = strings.TrimSuffix(result, "/"+attackerVal) + "/" + victimVal
			}
			// Also handle query params
			result = strings.ReplaceAll(result, "="+attackerVal+"&", "="+victimVal+"&")
			if strings.HasSuffix(result, "="+attackerVal) {
				result = strings.TrimSuffix(result, "="+attackerVal) + "=" + victimVal
			}
		}
	}

	return result
}

// BuildSwappedBody replaces IDs in request body
func BuildSwappedBody(originalBody string, attackerParams, victimParams map[string]string) string {
	result := originalBody

	// Replace placeholders
	for key, val := range victimParams {
		placeholders := []string{
			"{" + key + "}",
			":" + key,
			"{{" + key + "}}",
		}
		for _, placeholder := range placeholders {
			result = strings.ReplaceAll(result, placeholder, val)
		}
	}

	// Replace attacker's values with victim's values
	for key, attackerVal := range attackerParams {
		if victimVal, ok := victimParams[key]; ok && attackerVal != victimVal {
			// JSON: "user_id": "123" -> "user_id": "456"
			result = strings.ReplaceAll(result, `"`+attackerVal+`"`, `"`+victimVal+`"`)
			// Also plain value replacement
			result = strings.ReplaceAll(result, attackerVal, victimVal)
		}
	}

	return result
}
