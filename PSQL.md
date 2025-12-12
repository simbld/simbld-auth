export DATABASE_URL=postgres://simbld:2929@localhost:5434/simbld_auth
psql "$DATABASE_URL" -c "SELECT version, checksum, applied_at FROM _sqlx_migrations ORDER BY version";

psql "$DATABASE_URL" -c "DELETE FROM _sqlx_migrations WHERE version = 9;"
sqlx migrate run

psql "$DATABASE_URL" -c "\d+ email_mfa_codes"

cargo sqlx prepare --workspace

cargo check

cargo sqlx prepare --workspace --database-url "$DATABASE_URL"