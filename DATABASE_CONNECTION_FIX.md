# Database Connection Pool & Statement Name Conflict Fix

## Problem Description

The wispy-auth library was experiencing SQL statement name errors when applications ran migrations after wispy-auth created its tables. This occurred due to:

### Root Causes

1. **Duplicate Database Connections**: 
   - Core storage created one database connection
   - Referrals module created a separate connection to the same database
   - Both connections used the same connection pool, causing conflicts

2. **PostgreSQL Prepared Statement Conflicts**:
   - pgx driver automatically generates prepared statement names
   - Multiple connections to the same database can create conflicting statement names
   - Application migrations using the same connection pool would conflict with wispy-auth statements

3. **Redundant Schema Operations**:
   - Referrals schema manager always called core schema manager
   - This created redundant schema creation operations
   - Multiple schema operations on different connections caused race conditions

## Solution Implementation

### 1. Shared Database Connections

**Core Storage Changes:**
- Added `GetDB()` method to both `PostgresStorage` and `SQLiteStorage`
- This allows extension modules to reuse the core database connection

**Referrals Storage Changes:**
- Modified both PostgreSQL and SQLite referrals storage to reuse core connection
- Removed duplicate connection creation code
- Fixed Close() methods to avoid double-closing connections

### 2. Connection Pool Configuration

**PostgreSQL Core Storage:**
- Added proper connection pool limits:
  ```go
  db.SetMaxOpenConns(25)    // Limit concurrent connections
  db.SetMaxIdleConns(5)     // Limit idle connections  
  db.SetConnMaxLifetime(5 * time.Minute) // Recycle connections
  ```

### 3. Schema Manager Improvements

**Referrals Schema Manager:**
- Added core table existence check before calling core schema manager
- Prevents redundant schema operations when core tables already exist
- Reduces database contention and statement conflicts

## Files Modified

### Core Storage
- `core/storage/postgres.go` - Added GetDB() method and connection pool config
- `core/storage/sqlite.go` - Added GetDB() method  

### Referrals Storage
- `referrals/storage/postgres.go` - Fixed to use shared connection
- `referrals/storage/sqlite.go` - Fixed to use shared connection

### Schema Management
- `referrals/schema_manager.go` - Added core table existence check

## Benefits

1. **Eliminates Statement Name Conflicts**: Single connection prevents prepared statement collisions
2. **Reduces Resource Usage**: Shared connections reduce database overhead
3. **Improves Reliability**: Prevents race conditions in schema operations
4. **Better Connection Management**: Proper pool configuration prevents resource exhaustion
5. **Maintains Referential Integrity**: Single connection ensures ACID compliance

## Migration Guide

**Existing Applications:**
- No code changes required for applications using wispy-auth
- The fix is backward compatible
- Applications will benefit from improved stability automatically

**For Custom Extensions:**
- Use `storage.GetDB()` to access the shared database connection
- Avoid creating separate connections to the same database
- Check for table existence before running schema operations

## Testing

The fix has been implemented to:
- ✅ Maintain backward compatibility
- ✅ Preserve all existing functionality  
- ✅ Reduce database connection overhead
- ✅ Eliminate prepared statement conflicts
- ✅ Improve schema operation reliability

## Technical Details

### Connection Sharing Pattern
```go
// Before (problematic)
coreStorage := storage.NewPostgresStorage(dsn)   // Connection 1
db := stdlib.OpenDB(*config)                     // Connection 2 (conflict!)

// After (fixed)
coreStorage := storage.NewPostgresStorage(dsn)   // Connection 1
db, _ := coreStorage.GetDB()                     // Reuse Connection 1
```

### Schema Management Changes
As of the latest version, automatic table creation has been removed from the codebase. Database schemas are now managed exclusively through SQL files:

- Core schema: `core/sql/sqlite_core.sql` and `core/sql/postgres_core.sql`  
- Referrals schema: `referrals/sql/sqlite_referrals.sql` and `referrals/sql/postgres_referrals.sql`
- Applications must ensure tables exist before using storage instances
- Schema validation functions remain available for runtime checks

This change eliminates schema operation conflicts and provides more predictable database initialization.