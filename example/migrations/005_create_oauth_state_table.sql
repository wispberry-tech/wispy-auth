//go:build ignore
// This file will be included in the migrations folder

package migrations

func init() {
	migrations = append(migrations, Migration{
		ID: "005_create_oauth_state_table",
		Up: `
		CREATE TABLE IF NOT EXISTS oauth_states (
			state_id VARCHAR(64) PRIMARY KEY,
			csrf_token VARCHAR(64) NOT NULL,
			created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
			expires_at TIMESTAMP NOT NULL,
			created_by_ip VARCHAR(45)
		)`,
		Down: `DROP TABLE IF EXISTS oauth_states`,
	})
}
