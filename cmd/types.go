package cmd

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// User represents a user context for testing
type User struct {
	Name    string            `json:"name"`
	Headers map[string]string `json:"headers"`
	Params  map[string]string `json:"params"`
}

// APIRequest represents a single API request to test
type APIRequest struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
	Params  map[string]string
}

// Finding represents a potential security issue
type Finding struct {
	Severity    string    `json:"severity"`
	Endpoint    string    `json:"endpoint"`
	Method      string    `json:"method"`
	Description string    `json:"description"`
	Evidence    string    `json:"evidence"`
	Timestamp   time.Time `json:"timestamp"`
}

// Scanner performs IDOR testing
type Scanner struct {
	Users     []User
	Requests  []APIRequest
	client    *http.Client
	rateDelay time.Duration
}

// NewScanner creates a new scanner instance
func NewScanner(users []User, requests []APIRequest) *Scanner {
	return &Scanner{
		Users:     users,
		Requests:  requests,
		rateDelay: 100 * time.Millisecond, // Default 10 req/sec
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// SetProxy configures an HTTP proxy (e.g., Burp Suite)
func (s *Scanner) SetProxy(proxyURL string) error {
	proxy, err := url.Parse(proxyURL)
	if err != nil {
		return err
	}

	s.client.Transport = &http.Transport{
		Proxy: http.ProxyURL(proxy),
		TLSClientConfig: &tls.Config{
			InsecureSkipVerify: true, // Required for Burp's self-signed cert
		},
	}
	return nil
}

// SetRateLimit sets requests per second
func (s *Scanner) SetRateLimit(requestsPerSecond int) {
	if requestsPerSecond > 0 {
		s.rateDelay = time.Second / time.Duration(requestsPerSecond)
	}
}

// Run executes the scan
func (s *Scanner) Run() []Finding {
	findings := []Finding{}

	for _, req := range s.Requests {
		if verbose {
			fmt.Printf("🔍 Testing: %s %s\n", req.Method, req.URL)
		}

		// Test 1: Cross-user access (bidirectional)
		for i, user1 := range s.Users {
			for j, user2 := range s.Users {
				if i == j {
					continue
				}

				// Try to access user2's resources with user1's credentials
				f := s.testCrossUserAccess(req, user1, user2)
				if f != nil {
					findings = append(findings, *f)
				}
			}
		}

		// Test 2: No authentication
		f := s.testNoAuth(req)
		if f != nil {
			findings = append(findings, *f)
		}
	}

	return findings
}

func (s *Scanner) testCrossUserAccess(req APIRequest, attacker User, victim User) *Finding {
	// Clone request and replace victim's params with attacker's auth
	testReq := s.buildRequest(req, attacker, victim.Params)
	if testReq == nil {
		return nil
	}

	resp, err := s.executeRequest(testReq)
	if err != nil {
		if verbose {
			fmt.Printf("   ⚠️  Error: %v\n", err)
		}
		return nil
	}
	defer resp.Body.Close()

	// Read response body for size comparison
	body, _ := io.ReadAll(resp.Body)

	// Check if attacker could access victim's resource
	if resp.StatusCode == 200 || resp.StatusCode == 201 {
		return &Finding{
			Severity:    "CRITICAL",
			Endpoint:    req.URL,
			Method:      req.Method,
			Description: fmt.Sprintf("User '%s' accessed resources belonging to '%s'", attacker.Name, victim.Name),
			Evidence:    fmt.Sprintf("Status: %d, Size: %d bytes (expected 403/404)", resp.StatusCode, len(body)),
			Timestamp:   time.Now(),
		}
	}

	return nil
}

func (s *Scanner) testNoAuth(req APIRequest) *Finding {
	// Clone request with no auth headers
	testReq := s.buildRequestNoAuth(req)
	if testReq == nil {
		return nil
	}

	resp, err := s.executeRequest(testReq)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// Check if endpoint is accessible without auth
	// Exclude common public endpoints
	if resp.StatusCode == 200 && len(body) > 50 {
		// Skip if response looks like an error page
		bodyStr := string(body)
		if strings.Contains(bodyStr, "unauthorized") || strings.Contains(bodyStr, "forbidden") {
			return nil
		}
		return &Finding{
			Severity:    "HIGH",
			Endpoint:    req.URL,
			Method:      req.Method,
			Description: "Endpoint accessible without authentication",
			Evidence:    fmt.Sprintf("Status: %d, Response size: %d bytes", resp.StatusCode, len(body)),
			Timestamp:   time.Now(),
		}
	}

	return nil
}

func (s *Scanner) buildRequest(req APIRequest, user User, params map[string]string) *http.Request {
	// Replace parameters in URL and body
	url := req.URL
	body := req.Body

	for key, val := range params {
		// Support multiple placeholder formats: {user_id}, :user_id, {{user_id}}
		placeholders := []string{
			fmt.Sprintf("{%s}", key),
			fmt.Sprintf(":%s", key),
			fmt.Sprintf("{{%s}}", key),
		}
		for _, placeholder := range placeholders {
			url = strings.ReplaceAll(url, placeholder, val)
			body = strings.ReplaceAll(body, placeholder, val)
		}
	}

	httpReq, err := http.NewRequest(req.Method, url, strings.NewReader(body))
	if err != nil {
		if verbose {
			fmt.Printf("   ⚠️  Failed to build request: %v\n", err)
		}
		return nil
	}

	// Add user's auth headers
	for key, val := range user.Headers {
		httpReq.Header.Set(key, val)
	}

	// Add original headers
	for key, val := range req.Headers {
		if _, exists := user.Headers[key]; !exists {
			httpReq.Header.Set(key, val)
		}
	}

	return httpReq
}

func (s *Scanner) buildRequestNoAuth(req APIRequest) *http.Request {
	httpReq, err := http.NewRequest(req.Method, req.URL, strings.NewReader(req.Body))
	if err != nil {
		return nil
	}

	// Only add non-auth headers (exclude auth, cookie, session)
	authKeywords := []string{"auth", "cookie", "session", "token", "x-api-key"}
	for key, val := range req.Headers {
		lowerKey := strings.ToLower(key)
		isAuth := false
		for _, kw := range authKeywords {
			if strings.Contains(lowerKey, kw) {
				isAuth = true
				break
			}
		}
		if !isAuth {
			httpReq.Header.Set(key, val)
		}
	}

	return httpReq
}

func (s *Scanner) executeRequest(req *http.Request) (*http.Response, error) {
	return s.client.Do(req)
}

func loadUsers(filename string) ([]User, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var data struct {
		Users []User `json:"users"`
	}

	if err := json.NewDecoder(file).Decode(&data); err != nil {
		return nil, err
	}

	return data.Users, nil
}
