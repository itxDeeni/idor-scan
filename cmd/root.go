package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	cfgFile        string
	collectionFile string
	openapiFile    string
	harFile        string
	usersFile      string
	outputFormat   string
	outputFile     string
	proxyURL       string
	timeoutSecs    int
	rateLimit      int
	workers        int
	verbose        bool
)

var rootCmd = &cobra.Command{
	Use:   "idor-scan",
	Short: "Automated IDOR & Access Control Testing for REST APIs",
	Long: `IDOR-Scan replays API requests with manipulated authentication contexts 
to identify Insecure Direct Object Reference (IDOR) and Broken Object-Level 
Authorization (BOLA) vulnerabilities.`,
	Run: runScan,
}

func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func init() {
	cobra.OnInitialize(initConfig)

	// Input sources
	rootCmd.Flags().StringVarP(&collectionFile, "collection", "c", "", "Postman collection file (JSON)")
	rootCmd.Flags().StringVarP(&openapiFile, "openapi", "o", "", "OpenAPI spec file (YAML/JSON)")
	rootCmd.Flags().StringVarP(&harFile, "har", "H", "", "HAR file from browser/proxy")
	
	// Required
	rootCmd.Flags().StringVarP(&usersFile, "users", "u", "", "User contexts file (JSON)")
	rootCmd.MarkFlagRequired("users")

	// Output
	rootCmd.Flags().StringVarP(&outputFormat, "format", "f", "text", "Output format: text, json, html (Pro)")
	rootCmd.Flags().StringVarP(&outputFile, "output", "O", "", "Save findings to file")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Verbose output")

	// Network
	rootCmd.Flags().StringVarP(&proxyURL, "proxy", "p", "", "Proxy URL (e.g., http://127.0.0.1:8080 for Burp)")
	rootCmd.Flags().IntVarP(&timeoutSecs, "timeout", "t", 30, "Request timeout in seconds")
	rootCmd.Flags().IntVarP(&rateLimit, "rate", "r", 10, "Requests per second")
	rootCmd.Flags().IntVarP(&workers, "workers", "w", 5, "Number of concurrent workers")
	
	// Config file
	rootCmd.PersistentFlags().StringVar(&cfgFile, "config", "", "config file (default is .idor-scan.yaml)")
}

func initConfig() {
	if cfgFile != "" {
		viper.SetConfigFile(cfgFile)
	} else {
		viper.AddConfigPath(".")
		viper.SetConfigType("yaml")
		viper.SetConfigName(".idor-scan")
	}

	viper.AutomaticEnv()

	if err := viper.ReadInConfig(); err == nil && verbose {
		fmt.Fprintln(os.Stderr, "Using config file:", viper.ConfigFileUsed())
	}
}

func runScan(cmd *cobra.Command, args []string) {
	fmt.Println("🔍 IDOR-Scan v0.1.0")
	fmt.Println()

	// Validate input
	if collectionFile == "" && openapiFile == "" && harFile == "" {
		fmt.Fprintln(os.Stderr, "Error: must specify one of --collection, --openapi, or --har")
		os.Exit(1)
	}

	// Load user contexts
	if verbose {
		fmt.Printf("📋 Loading user contexts from: %s\n", usersFile)
	}
	
	users, err := loadUsers(usersFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading users: %v\n", err)
		os.Exit(1)
	}

	if verbose {
		fmt.Printf("✅ Loaded %d user contexts\n\n", len(users))
	}

	// Load API requests
	var requests []APIRequest
	
	if collectionFile != "" {
		if verbose {
			fmt.Printf("📦 Parsing Postman collection: %s\n", collectionFile)
		}
		requests, err = parsePostmanCollection(collectionFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing collection: %v\n", err)
			os.Exit(1)
		}
	} else if openapiFile != "" {
		if verbose {
			fmt.Printf("📦 Parsing OpenAPI spec: %s\n", openapiFile)
		}
		requests, err = parseOpenAPISpec(openapiFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing OpenAPI spec: %v\n", err)
			os.Exit(1)
		}
	} else if harFile != "" {
		if verbose {
			fmt.Printf("📦 Parsing HAR file: %s\n", harFile)
		}
		requests, err = parseHARFile(harFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error parsing HAR file: %v\n", err)
			os.Exit(1)
		}
	}

	if verbose {
		fmt.Printf("✅ Loaded %d API requests\n\n", len(requests))
		fmt.Println("🚀 Starting IDOR scan...")
		fmt.Println()
	}

	// Run scan with baseline comparison for accuracy
	scanner := NewScanner(users, requests)
	
	// Configure proxy if specified
	if proxyURL != "" {
		if verbose {
			fmt.Printf("🔌 Using proxy: %s\n", proxyURL)
		}
		if err := scanner.SetProxy(proxyURL); err != nil {
			fmt.Fprintf(os.Stderr, "Error setting proxy: %v\n", err)
			os.Exit(1)
		}
	}
	
	// Configure rate limit
	scanner.SetRateLimit(rateLimit)
	
	// Run scan (concurrent if workers > 1)
	var findings []Finding
	if workers > 1 {
		findings = scanner.RunWithBaselineConcurrent(workers)
	} else {
		findings = scanner.RunWithBaseline()
	}

	// Output results
	var output string
	if outputFormat == "json" {
		output = formatJSON(findings)
		if outputFile == "" {
			fmt.Println(output)
		}
	} else if outputFormat == "html" {
		output = formatHTML(findings)
		if outputFile == "" {
			fmt.Println(output)
		}
	} else {
		outputText(findings)
	}

	// Save to file if specified
	if outputFile != "" {
		if outputFormat == "text" {
			output = formatJSON(findings) // Default to JSON for file output
		}
		if err := os.WriteFile(outputFile, []byte(output), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing output file: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("💾 Findings saved to: %s\n", outputFile)
	}

	// Summary
	fmt.Println()
	fmt.Printf("📊 Scan complete: %d findings\n", len(findings))
	
	critical := 0
	high := 0
	medium := 0
	
	for _, f := range findings {
		switch f.Severity {
		case "CRITICAL":
			critical++
		case "HIGH":
			high++
		case "MEDIUM":
			medium++
		}
	}
	
	if critical > 0 {
		fmt.Printf("   🔴 Critical: %d\n", critical)
	}
	if high > 0 {
		fmt.Printf("   🟠 High: %d\n", high)
	}
	if medium > 0 {
		fmt.Printf("   🟡 Medium: %d\n", medium)
	}
}
