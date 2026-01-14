package cmd

import (
	"encoding/json"
	"os"
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
