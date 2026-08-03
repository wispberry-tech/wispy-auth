## Quick Commands

### Testing
```bash
go test ./...                          # Run all tests
go test -v -race -coverprofile=coverage.out ./...  # Tests with coverage & race detection
go test -run TestAuth ./core           # Run specific test suite
go test -run TestUserRegistration ./   # Run specific test
```

### Code Quality
```bash
gofmt -s -l .            # Check formatting (shows unformatted files)
gofmt -s -w .            # Auto-format all files
go install github.com/securego/gosec/v2/cmd/gosec@latest  # Install security scanner
gosec ./...              # Run security scan
```

### Building & Running
```bash
go build ./...           # Build the library
cd examples/core && go run main.go  # Run the example application (starts on :8080)
```

### Releasing
```bash
./release                # Interactive script to create and push version tags (e.g., v1.0.0)
# Alternatively: git tag v1.0.0 && git push origin v1.0.0
```
