# IDOR-Scan

**Automated IDOR & Access Control Testing for REST APIs**

IDOR-Scan replays API requests with manipulated authentication contexts to identify Insecure Direct Object Reference (IDOR) and Broken Object-Level Authorization (BOLA) vulnerabilities.

```bash
idor-scan --collection api.postman.json --users users.json
```

---

## Why IDOR-Scan?

**IDOR vulnerabilities are the #1 API security issue**, but testing for them manually is tedious:
- Swapping user IDs across dozens of endpoints
- Testing with/without authentication
- Comparing responses for data leakage

IDOR-Scan automates this entire workflow.

---

## Features

### ✅ Free (OSS)

- ✅ Import Postman collections & OpenAPI specs
- ✅ Replay requests with swapped user contexts
- ✅ Detect response anomalies (status codes, size differences)
- ✅ CLI output with flagged endpoints
- ✅ Export to JSON

### 🔒 Pro ($19/month or $299 one-time)

- 📊 **HTML/PDF Reports** — Professional findings reports for clients
- 🔄 **CI/CD Integration** — Run as part of your pipeline
- 🧪 **Role Matrix Testing** — Test admin/user/guest role combinations
- 📈 **Response Diffing** — Semantic comparison of JSON responses
- 🎯 **Custom Rules** — Define your own IDOR patterns
- ⚡ **Priority Support** — Direct access to security experts

[Get Pro →](https://idor-scan.dev/pricing)

---

## Installation

```bash
# macOS/Linux
curl -fsSL https://idor-scan.dev/install.sh | sh

# Or with Go
go install github.com/itxdeeni/idor-scan@latest

# Or download binary
https://github.com/itxdeeni/idor-scan/releases
```

---

## Quick Start

### 1. Prepare User Contexts

Create `users.json`:

```json
{
  "users": [
    {
      "name": "alice",
      "headers": {
        "Authorization": "Bearer eyJhbGc..."
      },
      "params": {
        "user_id": "123"
      }
    },
    {
      "name": "bob",
      "headers": {
        "Authorization": "Bearer eyJzdWI..."
      },
      "params": {
        "user_id": "456"
      }
    }
  ]
}
```

### 2. Run Scan

```bash
# From Postman collection
idor-scan --collection api.postman.json --users users.json

# From OpenAPI spec
idor-scan --openapi swagger.yaml --users users.json

# From HAR file
idor-scan --har traffic.har --users users.json
```

### 3. Review Findings

```
[CRITICAL] GET /api/users/{user_id}/orders
  ✗ User 'bob' accessed user_id=123 → 200 OK (expected 403)
  
[HIGH] GET /api/profile/{id}
  ✗ Response size: 1247 bytes with auth, 1238 bytes without auth
  ✗ Potential data leakage without authentication

[MEDIUM] DELETE /api/posts/{post_id}
  ✗ User 'alice' deleted post_id=789 (owned by bob)
```

---

## How It Works

1. **Import** — Parses Postman/OpenAPI/HAR into request templates
2. **Replay** — Executes requests with:
   - Swapped user credentials
   - Missing authentication
   - Modified path/body parameters
3. **Detect** — Flags anomalies:
   - 200 responses when expecting 403/404
   - Identical responses across different users
   - Response size differences indicating data leakage
4. **Report** — Outputs findings with reproduction steps

---

## Configuration

`.idor-scan.yaml`:

```yaml
target: "https://api.example.com"
timeout: 30s
concurrency: 5
ignore_endpoints:
  - "/health"
  - "/metrics"
detection:
  flag_status_codes:
    - 200
    - 201
  suspicious_size_diff: 50  # bytes
```

---

## Use Cases

**Bug Bounty Hunters:**
- Automate IDOR hunting across large attack surfaces
- Proven findings = higher bounties

**Security Teams:**
- Pre-deployment API security testing
- Regression testing for access control

**Penetration Testers:**
- Include in API audit workflows
- Professional reports for clients (Pro)

---

## Security Audits & Consulting

Need help securing your APIs?

We offer:
- **API Access Control Audits** — $500–$2,000
- **Custom IDOR Rule Development** — $300–$1,000
- **Team Training** — Security testing best practices

📧 Contact: zahradeenmuazu@yahoo.com

---

## Examples

More examples in [`/examples`](./examples):
- E-commerce API testing
- Multi-tenant SaaS
- Mobile backend APIs
- GraphQL endpoints

---

## Roadmap

- [x] Postman collection support
- [x] Basic IDOR detection
- [x] OpenAPI 3.0 support
- [x] HAR file import
- [ ] GraphQL introspection
- [x] Rate limiting & retry logic
- [ ] Session management

---

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md)

---

## License

MIT License — See [LICENSE](LICENSE)

**Pro version** is licensed separately. See [pricing](https://idor-scan.dev/pricing).

---

## Disclaimer

This tool is for **authorized security testing only**. Unauthorized access testing is illegal.

Always obtain written permission before testing third-party systems.

---

## Star History

If IDOR-Scan helped you find bugs or secure your APIs, consider ⭐️ starring the repo!

---

**Built by security researchers, for security researchers.**

[Documentation](https://docs.idor-scan.dev) | [Discord](https://discord.gg/idor-scan) | [Twitter](https://x.com/itxdeeni)
