# Contributing to Wispy Auth

We welcome contributions to Wispy Auth! This document provides guidelines and information for contributors.

## 🚀 Getting Started

### Development Setup

1. **Clone the repository**
   ```bash
   git clone https://github.com/wispberry-tech/wispy-auth.git
   cd wispy-auth
   ```

2. **Install dependencies**
   ```bash
   go mod download
   ```

3. **Run tests**
   ```bash
   go test ./...
   ```

4. **Run the example**
   ```bash
   cd examples/core
   go run main.go
   ```

## 🧪 Testing

### Running Tests

```bash
# Run all tests
go test ./...

# Run tests with coverage
go test -cover ./...

# Run specific test suites
go test -run TestAuth ./core
```

### Test Coverage

We aim for high test coverage. Please ensure:
- All new features have corresponding tests
- All bug fixes include regression tests
- Tests cover both success and error cases

## 📝 Code Style

### Go Standards

- Follow standard Go formatting (`go fmt`)
- Use `gofmt` and `goimports` for consistent formatting
- Follow Go naming conventions
- Write clear, concise, and well-documented code

### Commit Messages

Use clear, descriptive commit messages:
- Start with a verb (Add, Fix, Update, etc.)
- Keep the first line under 50 characters
- Provide detailed description if needed

Examples:
```
Add rate limiting middleware
Fix password validation bug in signup handler
Update README with new OAuth providers
```

## 🐛 Reporting Issues

### Bug Reports

When reporting bugs, please include:
- Go version (`go version`)
- Operating system
- Steps to reproduce
- Expected vs actual behavior
- Error messages/logs

### Feature Requests

For feature requests, please:
- Describe the problem you're trying to solve
- Explain why existing solutions don't work
- Provide examples of how you'd like to use the feature

## 🔄 Pull Request Process

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **Make your changes**
4. **Add tests** for new functionality
5. **Ensure all tests pass** (`go test ./...`)
6. **Update documentation** if needed
7. **Commit your changes** (`git commit -m 'Add amazing feature'`)
8. **Push to the branch** (`git push origin feature/amazing-feature`)
9. **Open a Pull Request**

### PR Requirements

- All tests must pass
- Code must be properly formatted
- Documentation updated if needed
- No breaking changes without discussion
- PR description explains the changes and why they're needed

## 📚 Documentation

### README Updates

When making changes that affect users:
- Update the main README.md
- Update core/README.md for core module changes
- Ensure examples are current and working

### Code Documentation

- Add comments for exported functions/types
- Update godoc comments when changing behavior
- Keep examples in documentation up-to-date

## 🔒 Security

### Security Issues

If you discover a security vulnerability:
- **DO NOT** create a public issue
- Email hello@wispberry.tech with details
- We aim to acknowledge receipt within 48 hours
- We will work with you on a fix and disclosure timeline

## 📋 Code of Conduct

### Our Standards

- Be respectful and inclusive
- Focus on constructive feedback
- Help newcomers learn and contribute
- Maintain professional communication

### Enforcement

Instances of unacceptable behavior may be reported to the maintainers.
All complaints will be reviewed and investigated promptly.

## 🙏 Acknowledgments

Thank you for contributing to Wispy Auth!

---

For questions or help, please open an issue or start a discussion on GitHub.