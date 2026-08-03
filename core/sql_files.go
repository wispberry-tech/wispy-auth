package core

import _ "embed"

//go:embed sql/sqlite_core.sql
var sqliteSchemaSQL string

//go:embed sql/postgres_core.sql
var postgresSchemaSQL string

// SQLiteSchemaSQL returns the embedded SQLite schema DDL.
func SQLiteSchemaSQL() string { return sqliteSchemaSQL }

// PostgresSchemaSQL returns the embedded PostgreSQL schema DDL.
func PostgresSchemaSQL() string { return postgresSchemaSQL }
