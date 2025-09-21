# Storage Package

This package provides storage interfaces and implementations for the wispy-auth authentication system.

## Architecture

The storage package uses a flat structure:

1. **Core Interface** (`storage.go`) - Defines the main `storage.Interface` and all data types
2. **Implementations** - Each storage backend is implemented directly in the package:
   - `sqlite.go` - SQLite implementation (pure Go, no CGO required)
   - `postgres.go` - PostgreSQL implementation

## Usage

### SQLite Storage (Recommended for Testing)

```go
import "github.com/wispberry-tech/wispy-auth/storage"

// In-memory storage for testing
store, err := storage.NewInMemorySQLiteStorage()
if err != nil {
    log.Fatal(err)
}
defer store.Close()

// File-based storage
store, err := storage.NewSQLiteStorage("./database.sqlite")
if err != nil {
    log.Fatal(err)
}
defer store.Close()
```

### PostgreSQL Storage (Production Ready)

```go
import "github.com/wispberry-tech/wispy-auth/storage"

store, err := storage.NewPostgresStorage("postgresql://user:password@localhost/dbname")
if err != nil {
    log.Fatal(err)
}
defer store.Close()
```

## Key Features

### Pure Go SQLite
- No CGO dependencies
- Works on all platforms
- Perfect for testing and development
- Uses `github.com/ncruces/go-sqlite3` driver

### PostgreSQL Production Ready
- Full feature implementation
- Enterprise-grade scalability
- Advanced security features
- Multi-tenant support

## Data Types

All storage implementations work with the same core types:

- `storage.User` - User accounts with comprehensive security fields
- `storage.Session` - Session tracking with device fingerprinting
- `storage.Tenant` - Multi-tenant organization support
- `storage.Role` - Role-based access control
- `storage.Permission` - Fine-grained permissions
- `storage.SecurityEvent` - Security audit logging
- `storage.OAuthState` - OAuth state management

## Interface Compliance

All implementations must satisfy the `storage.Interface`:

```go
type Interface interface {
    // User operations
    CreateUser(user *User) error
    GetUserByEmail(email, provider string) (*User, error)
    GetUserByEmailAnyProvider(email string) (*User, error)
    // ... and many more methods
}
```

## Adding New Storage Backends

To add a new storage backend:

1. Create a new subpackage under `storage/`
2. Implement the `storage.Interface`
3. Provide a constructor function that returns `storage.Interface`
4. Add comprehensive tests

Example structure:
```
storage/
├── newstorage/
│   ├── newstorage.go      # Main implementation
│   ├── constructor.go     # Public constructor
│   └── newstorage_test.go # Tests
```

## Migration from Legacy Storage

The old storage implementations (`postgres_storage.go`, `sqlite_storage.go`) are being migrated to this new structure. The migration provides:

- Better organization and maintainability
- Cleaner separation of concerns
- Easier testing with different backends
- Standardized interfaces across all storage types

## Testing

Use the SQLite in-memory storage for fast, isolated testing:

```go
store, err := storage.NewInMemorySQLiteStorage()
// ... run tests
store.Close()
```

This creates a fresh database for each test with no external dependencies.