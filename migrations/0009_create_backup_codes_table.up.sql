CREATE TABLE backup_codes
(
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash VARCHAR(255) NOT NULL,
    code_index INTEGER NOT NULL,
    batch_id   UUID    NOT NULL,
    used BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    used_at TIMESTAMP WITH TIME ZONE
);
-- Index on User_id for Quick Research
CREATE INDEX backup_codes_user_id_idx ON backup_codes(user_id);

-- Composite index to quickly find the unused codes of a user
CREATE INDEX backup_codes_user_id_used_idx ON backup_codes (user_id, used);

-- Index on batch_id to find all the codes of the same batch
-- CREATE INDEX backup_codes_batch_id_idx ON backup_codes(batch_id);

-- Index on the date of use for audit
-- CREATE INDEX backup_codes_used_at_idx ON backup_codes(used_at);

-- Composite index for lots management by date
-- CREATE INDEX backup_codes_user_batch_created_idx ON backup_codes(user_id, batch_id, created_at);

-- Index for security analyzes
-- CREATE INDEX backup_codes_created_used_idx ON backup_codes(created_at, used);

-- Index for Lot Administration
-- CREATE INDEX backup_codes_batch_index_idx ON backup_codes(batch_id, code_index);