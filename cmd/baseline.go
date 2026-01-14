package cmd

import (
	"fmt"
	"io"
	"net/http"
	"time"
)

// Baseline stores original response data for comparison
type Baseline struct {
	StatusCode int
	BodySize   int
	BodyHash   string
}

// BaselineMap stores baselines per endpoint+user
type BaselineMap map[string]map[string]Baseline // endpoint -> user -> baseline

// CaptureBaselines gets the legitimate response for each user on each endpoint
func (s *Scanner) CaptureBaselines() BaselineMap {
	baselines := make(BaselineMap)

	for _, req := range s.Requests {
		endpoint := fmt.Sprintf("%s %s", req.Method, req.URL)
		baselines[endpoint] = make(map[string]Baseline)

		for _, user := range s.Users {
			if verbose {
				fmt.Printf("📸 Baseline: %s as %s\n", endpoint, user.Name)
			}

			testReq := s.buildRequest(req, user, user.Params)
			if testReq == nil {
				continue
			}

			resp, err := s.executeRequest(testReq)
			if err != nil {
				continue
			}

			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()

			baselines[endpoint][user.Name] = Baseline{
				StatusCode: resp.StatusCode,
				BodySize:   len(body),
			}

			// Rate limit
			time.Sleep(s.rateDelay)
		}
	}

	return baselines
}

// RunWithBaseline executes scan with baseline comparison for accuracy
func (s *Scanner) RunWithBaseline() []Finding {
	findings := []Finding{}

	if verbose {
		fmt.Println("📊 Capturing baselines...")
		fmt.Println()
	}

	baselines := s.CaptureBaselines()

	if verbose {
		fmt.Println()
		fmt.Println("🚀 Starting IDOR tests...")
		fmt.Println()
	}

	for _, req := range s.Requests {
		endpoint := fmt.Sprintf("%s %s", req.Method, req.URL)

		if verbose {
			fmt.Printf("🔍 Testing: %s\n", endpoint)
		}

		// Cross-user access test with baseline comparison
		for _, attacker := range s.Users {
			for _, victim := range s.Users {
				if attacker.Name == victim.Name {
					continue
				}

				f := s.testCrossUserWithBaseline(req, attacker, victim, baselines)
				if f != nil {
					findings = append(findings, *f)
				}

				// Rate limit
				time.Sleep(s.rateDelay)
			}
		}

		// No auth test
		f := s.testNoAuth(req)
		if f != nil {
			findings = append(findings, *f)
		}

		time.Sleep(s.rateDelay)
	}

	return findings
}

func (s *Scanner) testCrossUserWithBaseline(req APIRequest, attacker User, victim User, baselines BaselineMap) *Finding {
	endpoint := fmt.Sprintf("%s %s", req.Method, req.URL)

	// Get victim's baseline (what they should see)
	victimBaseline, ok := baselines[endpoint][victim.Name]
	if !ok {
		return nil
	}

	// Build request with improved ID swapping
	// Uses attacker's auth but accesses victim's resources
	testReq := s.buildRequestWithSwap(req, attacker, victim)
	if testReq == nil {
		return nil
	}

	resp, err := s.executeRequest(testReq)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)

	// Compare against baseline
	if resp.StatusCode == 200 || resp.StatusCode == 201 {
		// Critical: same size as victim's legitimate response
		sizeDiff := abs(len(body) - victimBaseline.BodySize)
		if sizeDiff < 50 && victimBaseline.BodySize > 0 {
			return &Finding{
				Severity:    "CRITICAL",
				Endpoint:    req.URL,
				Method:      req.Method,
				Description: fmt.Sprintf("User '%s' accessed '%s's data (response matches victim's baseline)", attacker.Name, victim.Name),
				Evidence:    fmt.Sprintf("Status: %d, Size: %d bytes (victim baseline: %d bytes)", resp.StatusCode, len(body), victimBaseline.BodySize),
				Timestamp:   time.Now(),
			}
		}

		// High: got 200 but different size (might be partial leak or different data)
		if len(body) > 50 {
			return &Finding{
				Severity:    "HIGH",
				Endpoint:    req.URL,
				Method:      req.Method,
				Description: fmt.Sprintf("User '%s' got 200 accessing '%s's resource (size differs from baseline)", attacker.Name, victim.Name),
				Evidence:    fmt.Sprintf("Status: %d, Size: %d bytes (victim baseline: %d bytes)", resp.StatusCode, len(body), victimBaseline.BodySize),
				Timestamp:   time.Now(),
			}
		}
	}

	return nil
}

func abs(x int) int {
	if x < 0 {
		return -x
	}
	return x
}

// RateLimiter controls request rate
type RateLimiter struct {
	delay time.Duration
	last  time.Time
}

func NewRateLimiter(requestsPerSecond int) *RateLimiter {
	return &RateLimiter{
		delay: time.Second / time.Duration(requestsPerSecond),
	}
}

func (r *RateLimiter) Wait() {
	elapsed := time.Since(r.last)
	if elapsed < r.delay {
		time.Sleep(r.delay - elapsed)
	}
	r.last = time.Now()
}

// SetTimeout configures HTTP client timeout
func (s *Scanner) SetTimeout(timeout time.Duration) {
	s.client.Timeout = timeout
}

// SetTransport configures custom transport (for proxy support)
func (s *Scanner) SetTransport(transport http.RoundTripper) {
	s.client.Transport = transport
}
