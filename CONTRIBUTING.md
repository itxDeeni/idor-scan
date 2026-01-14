# Contributing to IDOR-Scan

Thank you for your interest in contributing!

## Quick Start

1. Fork the repo
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Make your changes
4. Add tests if applicable
5. Run: `go test ./...`
6. Commit: `git commit -m 'Add amazing feature'`
7. Push: `git push origin feature/amazing-feature`
8. Open a Pull Request

## Development Setup

```bash
# Clone your fork
git clone https://github.com/itxdeeni/idor-scan.git
cd idor-scan

# Install dependencies
go mod download

# Build
go build -o idor-scan

# Test
go test ./...
```

## What to Contribute

**High Priority:**
- New parsers (OpenAPI, HAR, Swagger)
- Detection heuristics (improve accuracy)
- Bug fixes

**Welcome:**
- Documentation improvements
- Example collections
- Test cases

**Please Discuss First:**
- Major architectural changes
- New paid features
- Breaking changes

## Code Style

- Follow standard Go formatting: `go fmt`
- Write meaningful commit messages
- Add comments for non-obvious logic
- Keep PRs focused (one feature/fix per PR)

## Testing

- Add tests for new detection logic
- Ensure existing tests pass
- Include example collections for new features

## Questions?

- Open an issue for discussion
- Join our Discord: https://discord.gg/idor-scan

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
