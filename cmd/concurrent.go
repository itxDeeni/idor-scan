package cmd

import (
	"fmt"
	"io"
	"sync"
	"time"
)

// ScanJob represents a single IDOR test to perform
type ScanJob struct {
	Request  APIRequest
	Attacker User
	Victim   User
	Baseline Baseline
}

// ScanResult contains the result of a scan job
type ScanResult struct {
	Finding *Finding
	Error   error
}

// RunWithBaselineConcurrent executes scan with worker pool
func (s *Scanner) RunWithBaselineConcurrent(workers int) []Finding {
	if workers <= 0 {
		workers = 5 // Default
	}

	if verbose {
		fmt.Println("📊 Capturing baselines...")
		fmt.Println()
	}

	baselines := s.CaptureBaselines()

	if verbose {
		fmt.Println()
		fmt.Printf("🚀 Starting IDOR tests with %d workers...\n", workers)
		fmt.Println()
	}

	// Create job channel
	jobs := make(chan ScanJob, len(s.Requests)*len(s.Users)*len(s.Users))
	results := make(chan ScanResult, len(s.Requests)*len(s.Users)*len(s.Users))

	// Start workers
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go s.worker(jobs, results, &wg)
	}

	// Queue jobs
	jobCount := 0
	for _, req := range s.Requests {
		endpoint := fmt.Sprintf("%s %s", req.Method, req.URL)

		if verbose {
			fmt.Printf("🔍 Queuing: %s\n", endpoint)
		}

		for _, attacker := range s.Users {
			for _, victim := range s.Users {
				if attacker.Name == victim.Name {
					continue
				}

				baseline, ok := baselines[endpoint][victim.Name]
				if !ok {
					continue
				}

				jobs <- ScanJob{
					Request:  req,
					Attacker: attacker,
					Victim:   victim,
					Baseline: baseline,
				}
				jobCount++
			}
		}
	}
	close(jobs)

	// Wait for workers to finish
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	findings := []Finding{}
	for result := range results {
		if result.Finding != nil {
			findings = append(findings, *result.Finding)
		}
	}

	// Also run no-auth tests (sequential, usually fewer)
	for _, req := range s.Requests {
		f := s.testNoAuth(req)
		if f != nil {
			findings = append(findings, *f)
		}
		time.Sleep(s.rateDelay)
	}

	return findings
}

func (s *Scanner) worker(jobs <-chan ScanJob, results chan<- ScanResult, wg *sync.WaitGroup) {
	defer wg.Done()

	for job := range jobs {
		finding := s.executeScanJob(job)
		results <- ScanResult{Finding: finding}
		time.Sleep(s.rateDelay)
	}
}

func (s *Scanner) executeScanJob(job ScanJob) *Finding {
	testReq := s.buildRequestWithSwap(job.Request, job.Attacker, job.Victim)
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
		sizeDiff := abs(len(body) - job.Baseline.BodySize)
		if sizeDiff < 50 && job.Baseline.BodySize > 0 {
			return &Finding{
				Severity:    "CRITICAL",
				Endpoint:    job.Request.URL,
				Method:      job.Request.Method,
				Description: fmt.Sprintf("User '%s' accessed '%s's data (response matches victim's baseline)", job.Attacker.Name, job.Victim.Name),
				Evidence:    fmt.Sprintf("Status: %d, Size: %d bytes (victim baseline: %d bytes)", resp.StatusCode, len(body), job.Baseline.BodySize),
				Timestamp:   time.Now(),
			}
		}

		if len(body) > 50 {
			return &Finding{
				Severity:    "HIGH",
				Endpoint:    job.Request.URL,
				Method:      job.Request.Method,
				Description: fmt.Sprintf("User '%s' got 200 accessing '%s's resource (size differs from baseline)", job.Attacker.Name, job.Victim.Name),
				Evidence:    fmt.Sprintf("Status: %d, Size: %d bytes (victim baseline: %d bytes)", resp.StatusCode, len(body), job.Baseline.BodySize),
				Timestamp:   time.Now(),
			}
		}
	}

	return nil
}
