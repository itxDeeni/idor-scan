package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// PostmanCollection represents a simplified Postman collection
type PostmanCollection struct {
	Info struct {
		Name string `json:"name"`
	} `json:"info"`
	Item []PostmanItem `json:"item"`
}

type PostmanItem struct {
	Name    string            `json:"name"`
	Request PostmanRequest    `json:"request"`
	Item    []PostmanItem     `json:"item"` // For folders
}

type PostmanRequest struct {
	Method string                   `json:"method"`
	Header []PostmanHeader          `json:"header"`
	URL    PostmanURL               `json:"url"`
	Body   PostmanBody              `json:"body"`
}

type PostmanHeader struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type PostmanURL struct {
	Raw  string `json:"raw"`
	Host []string `json:"host"`
	Path []string `json:"path"`
}

type PostmanBody struct {
	Mode string `json:"mode"`
	Raw  string `json:"raw"`
}

func parsePostmanCollection(filename string) ([]APIRequest, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var collection PostmanCollection
	if err := json.NewDecoder(file).Decode(&collection); err != nil {
		return nil, err
	}

	requests := []APIRequest{}
	
	// Recursively parse items
	for _, item := range collection.Item {
		requests = append(requests, parseItems(item)...)
	}

	return requests, nil
}

func parseItems(item PostmanItem) []APIRequest {
	requests := []APIRequest{}

	// If it's a folder, recurse
	if len(item.Item) > 0 {
		for _, subItem := range item.Item {
			requests = append(requests, parseItems(subItem)...)
		}
		return requests
	}

	// Parse single request
	if item.Request.Method != "" {
		headers := make(map[string]string)
		for _, h := range item.Request.Header {
			headers[h.Key] = h.Value
		}

		req := APIRequest{
			Method:  item.Request.Method,
			URL:     item.Request.URL.Raw,
			Headers: headers,
			Body:    item.Request.Body.Raw,
			Params:  make(map[string]string),
		}

		requests = append(requests, req)
	}

	return requests
}

// ============================================================================
// OpenAPI / Swagger Parser
// ============================================================================

// OpenAPISpec represents an OpenAPI 3.x specification
type OpenAPISpec struct {
	OpenAPI string                 `json:"openapi" yaml:"openapi"`
	Swagger string                 `json:"swagger" yaml:"swagger"` // For Swagger 2.0
	Info    OpenAPIInfo            `json:"info" yaml:"info"`
	Servers []OpenAPIServer        `json:"servers" yaml:"servers"`
	Host    string                 `json:"host" yaml:"host"`       // Swagger 2.0
	BasePath string                `json:"basePath" yaml:"basePath"` // Swagger 2.0
	Schemes []string               `json:"schemes" yaml:"schemes"` // Swagger 2.0
	Paths   map[string]PathItem    `json:"paths" yaml:"paths"`
}

type OpenAPIInfo struct {
	Title   string `json:"title" yaml:"title"`
	Version string `json:"version" yaml:"version"`
}

type OpenAPIServer struct {
	URL string `json:"url" yaml:"url"`
}

type PathItem struct {
	Get     *Operation `json:"get" yaml:"get"`
	Post    *Operation `json:"post" yaml:"post"`
	Put     *Operation `json:"put" yaml:"put"`
	Patch   *Operation `json:"patch" yaml:"patch"`
	Delete  *Operation `json:"delete" yaml:"delete"`
	Options *Operation `json:"options" yaml:"options"`
	Head    *Operation `json:"head" yaml:"head"`
}

type Operation struct {
	OperationID string       `json:"operationId" yaml:"operationId"`
	Summary     string       `json:"summary" yaml:"summary"`
	Parameters  []Parameter  `json:"parameters" yaml:"parameters"`
	RequestBody *RequestBody `json:"requestBody" yaml:"requestBody"`
}

type Parameter struct {
	Name     string `json:"name" yaml:"name"`
	In       string `json:"in" yaml:"in"` // path, query, header, cookie
	Required bool   `json:"required" yaml:"required"`
	Schema   Schema `json:"schema" yaml:"schema"`
}

type Schema struct {
	Type string `json:"type" yaml:"type"`
}

type RequestBody struct {
	Content map[string]MediaType `json:"content" yaml:"content"`
}

type MediaType struct {
	Schema Schema `json:"schema" yaml:"schema"`
}

func parseOpenAPISpec(filename string) ([]APIRequest, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var spec OpenAPISpec

	// Try YAML first, then JSON
	if err := yaml.Unmarshal(data, &spec); err != nil {
		if err := json.Unmarshal(data, &spec); err != nil {
			return nil, fmt.Errorf("failed to parse as YAML or JSON: %w", err)
		}
	}

	// Determine base URL
	baseURL := ""
	if len(spec.Servers) > 0 {
		baseURL = strings.TrimSuffix(spec.Servers[0].URL, "/")
	} else if spec.Host != "" {
		// Swagger 2.0 format
		scheme := "https"
		if len(spec.Schemes) > 0 {
			scheme = spec.Schemes[0]
		}
		baseURL = fmt.Sprintf("%s://%s%s", scheme, spec.Host, spec.BasePath)
	}

	requests := []APIRequest{}

	for path, pathItem := range spec.Paths {
		operations := map[string]*Operation{
			"GET":     pathItem.Get,
			"POST":    pathItem.Post,
			"PUT":     pathItem.Put,
			"PATCH":   pathItem.Patch,
			"DELETE":  pathItem.Delete,
			"OPTIONS": pathItem.Options,
			"HEAD":    pathItem.Head,
		}

		for method, op := range operations {
			if op == nil {
				continue
			}

			// Convert path params from {id} format (already correct)
			url := baseURL + path

			req := APIRequest{
				Method:  method,
				URL:     url,
				Headers: make(map[string]string),
				Params:  make(map[string]string),
			}

			// Extract parameters
			for _, param := range op.Parameters {
				if param.In == "header" {
					req.Headers[param.Name] = fmt.Sprintf("{%s}", param.Name)
				}
			}

			requests = append(requests, req)
		}
	}

	return requests, nil
}

// ============================================================================
// HAR (HTTP Archive) Parser
// ============================================================================

// HARFile represents a HAR file structure
type HARFile struct {
	Log HARLog `json:"log"`
}

type HARLog struct {
	Entries []HAREntry `json:"entries"`
}

type HAREntry struct {
	Request HARRequest `json:"request"`
}

type HARRequest struct {
	Method      string      `json:"method"`
	URL         string      `json:"url"`
	Headers     []HARHeader `json:"headers"`
	PostData    *HARPostData `json:"postData"`
}

type HARHeader struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type HARPostData struct {
	MimeType string `json:"mimeType"`
	Text     string `json:"text"`
}

func parseHARFile(filename string) ([]APIRequest, error) {
	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, err
	}

	var har HARFile
	if err := json.Unmarshal(data, &har); err != nil {
		return nil, fmt.Errorf("failed to parse HAR file: %w", err)
	}

	requests := []APIRequest{}
	seen := make(map[string]bool) // Dedupe by method+URL

	for _, entry := range har.Log.Entries {
		key := entry.Request.Method + " " + entry.Request.URL
		if seen[key] {
			continue
		}
		seen[key] = true

		headers := make(map[string]string)
		for _, h := range entry.Request.Headers {
			// Skip pseudo-headers and common browser headers
			lowerName := strings.ToLower(h.Name)
			if strings.HasPrefix(lowerName, ":") ||
				lowerName == "host" ||
				lowerName == "connection" ||
				lowerName == "accept-encoding" ||
				lowerName == "accept-language" ||
				lowerName == "user-agent" {
				continue
			}
			headers[h.Name] = h.Value
		}

		body := ""
		if entry.Request.PostData != nil {
			body = entry.Request.PostData.Text
		}

		req := APIRequest{
			Method:  entry.Request.Method,
			URL:     entry.Request.URL,
			Headers: headers,
			Body:    body,
			Params:  make(map[string]string),
		}

		requests = append(requests, req)
	}

	return requests, nil
}
