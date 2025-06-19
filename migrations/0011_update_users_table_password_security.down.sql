ALTER TABLE users
    DROP COLUMN IF EXISTS password_changed_at,
    DROP COLUMN IF EXISTS password_history,
    DROP COLUMN IF EXISTS password_expires_at,
    DROP COLUMN IF EXISTS require_password_change;