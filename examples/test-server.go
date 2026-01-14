// Vulnerable test server for IDOR-Scan demo
// Run: go run examples/test-server.go
// Then: ./idor-scan -c examples/local-collection.postman.json -u examples/users.json -v

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// Simulated database
var users = map[string]map[string]interface{}{
	"123": {"id": "123", "name": "Alice", "email": "alice@example.com", "ssn": "111-22-3333"},
	"456": {"id": "456", "name": "Bob", "email": "bob@example.com", "ssn": "444-55-6666"},
}

var orders = map[string][]map[string]interface{}{
	"123": {{"id": "order-1", "amount": 99.99, "item": "Secret Alice Item"}},
	"456": {{"id": "order-2", "amount": 149.99, "item": "Secret Bob Item"}},
}

func main() {
	// VULNERABLE: No authorization check - just checks if token exists
	http.HandleFunc("/api/users/", func(w http.ResponseWriter, r *http.Request) {
		// Extract user_id from path
		parts := strings.Split(r.URL.Path, "/")
		if len(parts) < 4 {
			http.Error(w, "Not found", 404)
			return
		}
		userID := parts[3]

		// Check auth header exists (but NOT if it matches the user!)
		auth := r.Header.Get("Authorization")
		if auth == "" {
			http.Error(w, `{"error": "unauthorized"}`, 401)
			return
		}

		// Check if requesting orders
		if len(parts) > 4 && parts[4] == "orders" {
			// VULNERABLE: Returns any user's orders if authenticated
			if orderList, ok := orders[userID]; ok {
				w.Header().Set("Content-Type", "application/json")
				json.NewEncoder(w).Encode(orderList)
				return
			}
			http.Error(w, "Not found", 404)
			return
		}

		// VULNERABLE: Returns any user's profile if authenticated
		if user, ok := users[userID]; ok {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(user)
			return
		}

		http.Error(w, "Not found", 404)
	})

	// Health check (intentionally public)
	http.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	})

	fmt.Println("🚀 Vulnerable test server running on http://localhost:8888")
	fmt.Println("   GET /api/users/{id}        - VULNERABLE (IDOR)")
	fmt.Println("   GET /api/users/{id}/orders - VULNERABLE (IDOR)")
	fmt.Println()
	fmt.Println("Test with:")
	fmt.Println("   ./idor-scan -c examples/local-collection.postman.json -u examples/users.json -v")

	http.ListenAndServe(":8888", nil)
}
