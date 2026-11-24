package storage

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"

	"github.com/wispberry-tech/wispy-auth/core"
)

var legacyTables = []string{
	"users",
	"user_security",
	"sessions",
	"security_events",
	"oauth_states",
	"password_reset_tokens",
	"two_factor_codes",
	"two_factor_backup_codes",
	"refresh_tokens",
}

func migrateSQLiteIDs(ctx context.Context, db *sql.DB) (returnErr error) {
	conn, err := db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("acquire SQLite connection for UUID migration: %w", err)
	}
	defer conn.Close()

	rows, err := conn.QueryContext(ctx, "PRAGMA table_info(users)")
	if err != nil {
		return fmt.Errorf("inspect SQLite users schema: %w", err)
	}
	legacy := false
	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, columnType string
		var defaultValue any
		if err := rows.Scan(&cid, &name, &columnType, &notNull, &defaultValue, &primaryKey); err != nil {
			rows.Close()
			return fmt.Errorf("read SQLite users schema: %w", err)
		}
		if name == "id" && strings.EqualFold(columnType, "INTEGER") {
			legacy = true
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return fmt.Errorf("iterate SQLite users schema: %w", err)
	}
	rows.Close()
	if !legacy {
		return nil
	}

	if _, err := conn.ExecContext(ctx, "PRAGMA foreign_keys = OFF"); err != nil {
		return fmt.Errorf("disable SQLite foreign keys for UUID migration: %w", err)
	}
	defer func() {
		if _, err := conn.ExecContext(context.Background(), "PRAGMA foreign_keys = ON"); err != nil && returnErr == nil {
			returnErr = fmt.Errorf("re-enable SQLite foreign keys after UUID migration: %w", err)
		}
	}()

	tx, err := conn.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin SQLite UUID migration: %w", err)
	}
	defer tx.Rollback()

	for _, table := range legacyTables {
		if _, err := tx.ExecContext(ctx, "CREATE TEMP TABLE "+table+"_legacy AS SELECT * FROM "+table); err != nil {
			return fmt.Errorf("copy legacy SQLite table %s: %w", table, err)
		}
	}
	for i := len(legacyTables) - 1; i >= 0; i-- {
		if _, err := tx.ExecContext(ctx, "DROP TABLE "+legacyTables[i]); err != nil {
			return fmt.Errorf("drop old SQLite table %s: %w", legacyTables[i], err)
		}
	}
	if _, err := tx.ExecContext(ctx, core.SQLiteSchemaSQL()); err != nil {
		return fmt.Errorf("create UUID SQLite schema: %w", err)
	}

	copies := []string{
		`INSERT INTO users (id, email, username, first_name, last_name, password_hash, avatar_url, provider, provider_id, email_verified, is_active, is_suspended, created_at, updated_at)
		 SELECT uuid, email, username, first_name, last_name, password_hash, avatar_url, provider, provider_id, email_verified, is_active, is_suspended, created_at, updated_at FROM users_legacy`,
		`INSERT INTO user_security (user_id, login_attempts, locked_until, last_login_at, last_login_ip, last_failed_login_at, last_failed_login_ip, password_changed_at, force_password_change, two_factor_enabled, two_factor_secret, two_factor_verified_at, created_at, updated_at)
		 SELECT u.uuid, s.login_attempts, s.locked_until, s.last_login_at, s.last_login_ip, s.last_failed_login_at, s.last_failed_login_ip, s.password_changed_at, s.force_password_change, s.two_factor_enabled, s.two_factor_secret, s.two_factor_verified_at, s.created_at, s.updated_at FROM user_security_legacy s LEFT JOIN users_legacy u ON u.id = s.user_id`,
		`INSERT INTO sessions (token, user_id, expires_at, last_accessed_at, user_agent, ip_address, device_fingerprint, is_active, created_at)
		 SELECT s.token, u.uuid, s.expires_at, s.last_accessed_at, s.user_agent, s.ip_address, s.device_fingerprint, s.is_active, s.created_at FROM sessions_legacy s LEFT JOIN users_legacy u ON u.id = s.user_id`,
		`INSERT INTO security_events (user_id, event_type, description, ip_address, user_agent, device_fingerprint, severity, success, metadata, created_at)
		 SELECT u.uuid, e.event_type, e.description, e.ip_address, e.user_agent, e.device_fingerprint, e.severity, e.success, e.metadata, e.created_at FROM security_events_legacy e LEFT JOIN users_legacy u ON u.id = e.user_id`,
		`INSERT INTO oauth_states (state, provider, redirect_url, expires_at, created_at)
		 SELECT state, provider, redirect_url, expires_at, created_at FROM oauth_states_legacy`,
		`INSERT INTO password_reset_tokens (user_id, token, expires_at, used_at, created_at)
		 SELECT u.uuid, t.token, t.expires_at, t.used_at, t.created_at FROM password_reset_tokens_legacy t LEFT JOIN users_legacy u ON u.id = t.user_id`,
		`INSERT INTO two_factor_codes (user_id, code, code_type, expires_at, used_at, created_at)
		 SELECT u.uuid, c.code, c.code_type, c.expires_at, c.used_at, c.created_at FROM two_factor_codes_legacy c LEFT JOIN users_legacy u ON u.id = c.user_id`,
		`INSERT INTO two_factor_backup_codes (user_id, code, used_at, created_at)
		 SELECT u.uuid, c.code, c.used_at, c.created_at FROM two_factor_backup_codes_legacy c LEFT JOIN users_legacy u ON u.id = c.user_id`,
		`INSERT INTO refresh_tokens (token, user_id, session_id, expires_at, created_at, last_used_at)
		 SELECT r.token, u.uuid, s.id, r.expires_at, r.created_at, r.last_used_at FROM refresh_tokens_legacy r LEFT JOIN users_legacy u ON u.id = r.user_id LEFT JOIN sessions_legacy old_s ON old_s.id = r.session_id LEFT JOIN sessions s ON s.token = old_s.token`,
	}
	for i, query := range copies {
		if _, err := tx.ExecContext(ctx, query); err != nil {
			return fmt.Errorf("copy legacy SQLite data set %d: %w", i+1, err)
		}
	}
	for i := len(legacyTables) - 1; i >= 0; i-- {
		if _, err := tx.ExecContext(ctx, "DROP TABLE "+legacyTables[i]+"_legacy"); err != nil {
			return fmt.Errorf("drop temporary SQLite table %s: %w", legacyTables[i], err)
		}
	}
	foreignKeyRows, err := tx.QueryContext(ctx, "PRAGMA foreign_key_check")
	if err != nil {
		return fmt.Errorf("check SQLite foreign keys after UUID migration: %w", err)
	}
	if foreignKeyRows.Next() {
		var table string
		var rowID, foreignKeyID sql.NullInt64
		var parent string
		if err := foreignKeyRows.Scan(&table, &rowID, &parent, &foreignKeyID); err != nil {
			foreignKeyRows.Close()
			return fmt.Errorf("read SQLite foreign key violation: %w", err)
		}
		foreignKeyRows.Close()
		return fmt.Errorf("UUID migration would break foreign key %s -> %s; migrate application-owned references first", table, parent)
	}
	if err := foreignKeyRows.Err(); err != nil {
		foreignKeyRows.Close()
		return fmt.Errorf("iterate SQLite foreign key check: %w", err)
	}
	foreignKeyRows.Close()
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit SQLite UUID migration: %w", err)
	}
	return nil
}

func migratePostgresIDs(ctx context.Context, db *sql.DB) error {
	var idType string
	err := db.QueryRowContext(ctx, `SELECT data_type FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'users' AND column_name = 'id'`).Scan(&idType)
	if errors.Is(err, sql.ErrNoRows) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect PostgreSQL users schema: %w", err)
	}
	if idType != "integer" && idType != "bigint" {
		return nil
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin PostgreSQL UUID migration: %w", err)
	}
	defer tx.Rollback()
	var currentIDType string
	err = tx.QueryRowContext(ctx, `SELECT data_type FROM information_schema.columns WHERE table_schema = current_schema() AND table_name = 'users' AND column_name = 'id'`).Scan(&currentIDType)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("recheck PostgreSQL users schema: %w", err)
	}
	if errors.Is(err, sql.ErrNoRows) || (currentIDType != "integer" && currentIDType != "bigint") {
		return nil
	}
	for _, table := range legacyTables {
		if _, err := tx.ExecContext(ctx, "CREATE TEMP TABLE "+table+"_legacy ON COMMIT DROP AS TABLE "+table); err != nil {
			return fmt.Errorf("copy legacy PostgreSQL table %s: %w", table, err)
		}
	}
	for i := len(legacyTables) - 1; i >= 0; i-- {
		if _, err := tx.ExecContext(ctx, "DROP TABLE "+legacyTables[i]); err != nil {
			return fmt.Errorf("drop old PostgreSQL table %s: %w", legacyTables[i], err)
		}
	}
	if _, err := tx.ExecContext(ctx, core.PostgresSchemaSQL()); err != nil {
		return fmt.Errorf("create UUID PostgreSQL schema: %w", err)
	}

	copies := []string{
		`INSERT INTO users (id, email, username, first_name, last_name, password_hash, avatar_url, provider, provider_id, email_verified, is_active, is_suspended, created_at, updated_at)
		 SELECT uuid, email, username, first_name, last_name, password_hash, avatar_url, provider, provider_id, email_verified, is_active, is_suspended, created_at, updated_at FROM users_legacy`,
		`INSERT INTO user_security (user_id, login_attempts, locked_until, last_login_at, last_login_ip, last_failed_login_at, last_failed_login_ip, password_changed_at, force_password_change, two_factor_enabled, two_factor_secret, two_factor_verified_at, created_at, updated_at)
		 SELECT u.uuid, s.login_attempts, s.locked_until, s.last_login_at, s.last_login_ip, s.last_failed_login_at, s.last_failed_login_ip, s.password_changed_at, s.force_password_change, s.two_factor_enabled, s.two_factor_secret, s.two_factor_verified_at, s.created_at, s.updated_at FROM user_security_legacy s LEFT JOIN users_legacy u ON u.id = s.user_id`,
		`INSERT INTO sessions (token, user_id, expires_at, last_accessed_at, user_agent, ip_address, device_fingerprint, is_active, created_at)
		 SELECT s.token, u.uuid, s.expires_at, s.last_accessed_at, s.user_agent, s.ip_address, s.device_fingerprint, s.is_active, s.created_at FROM sessions_legacy s LEFT JOIN users_legacy u ON u.id = s.user_id`,
		`INSERT INTO security_events (user_id, event_type, description, ip_address, user_agent, device_fingerprint, severity, success, metadata, created_at)
		 SELECT u.uuid, e.event_type, e.description, e.ip_address, e.user_agent, e.device_fingerprint, e.severity, e.success, e.metadata, e.created_at FROM security_events_legacy e LEFT JOIN users_legacy u ON u.id = e.user_id`,
		`INSERT INTO oauth_states (state, provider, redirect_url, expires_at, created_at)
		 SELECT state, provider, redirect_url, expires_at, created_at FROM oauth_states_legacy`,
		`INSERT INTO password_reset_tokens (user_id, token, expires_at, used_at, created_at)
		 SELECT u.uuid, t.token, t.expires_at, t.used_at, t.created_at FROM password_reset_tokens_legacy t LEFT JOIN users_legacy u ON u.id = t.user_id`,
		`INSERT INTO two_factor_codes (user_id, code, code_type, expires_at, used_at, created_at)
		 SELECT u.uuid, c.code, c.code_type, c.expires_at, c.used_at, c.created_at FROM two_factor_codes_legacy c LEFT JOIN users_legacy u ON u.id = c.user_id`,
		`INSERT INTO two_factor_backup_codes (user_id, code, used_at, created_at)
		 SELECT u.uuid, c.code, c.used_at, c.created_at FROM two_factor_backup_codes_legacy c LEFT JOIN users_legacy u ON u.id = c.user_id`,
		`INSERT INTO refresh_tokens (token, user_id, session_id, expires_at, created_at, last_used_at)
		 SELECT r.token, u.uuid, s.id, r.expires_at, r.created_at, r.last_used_at FROM refresh_tokens_legacy r LEFT JOIN users_legacy u ON u.id = r.user_id LEFT JOIN sessions_legacy old_s ON old_s.id = r.session_id LEFT JOIN sessions s ON s.token = old_s.token`,
	}
	for i, query := range copies {
		if _, err := tx.ExecContext(ctx, query); err != nil {
			return fmt.Errorf("copy legacy PostgreSQL data set %d: %w", i+1, err)
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit PostgreSQL UUID migration: %w", err)
	}
	return nil
}
