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

-- Composite index to find the unused codes of a user
CREATE INDEX backup_codes_user_id_used_idx ON backup_codes (user_id, used);

-- Index on batch_id to find all the codes of the same batch
-- CREATE INDEX backup_codes_batch_id_idx ON backup_codes(batch_id);

-- Index on the date of use for audit
-- CREATE INDEX backup_codes_used_at_idx ON backup_codes(used_at);

-- Composite index for lots' management by date
-- CREATE INDEX backup_codes_user_batch_created_idx ON backup_codes(user_id, batch_id, created_at);

-- Index for security analyses
-- CREATE INDEX backup_codes_created_used_idx ON backup_codes(created_at, used);

-- Index for Lot Administration
-- SQL
CREATE TABLE backup_codes
(
    id            UUID PRIMARY KEY                  DEFAULT gen_random_uuid(),
    user_id       UUID                     NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    mfa_method_id UUID,                     -- optionnel, référence vers table mfa_methods
    code_hash     VARCHAR(255)             NOT NULL,
    code          VARCHAR(255),             -- code en clair si nécessaire (nullable)
    code_index    INTEGER                  NOT NULL,
    batch_id      UUID                     NOT NULL,
    used          BOOLEAN                  NOT NULL DEFAULT FALSE,
    created_at    TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    used_at       TIMESTAMP WITH TIME ZONE, -- existant pour compatibilité
    last_used_at  TIMESTAMP WITH TIME ZONE  -- nouvelle colonne demandée
);

-- Index on User_id for Quick Research
CREATE INDEX IF NOT EXISTS backup_codes_user_id_idx ON backup_codes(user_id);

-- Composite index to find the unused codes of a user
CREATE INDEX IF NOT EXISTS backup_codes_user_id_used_idx ON backup_codes (user_id, used);

-- Index on batch_id to find all the codes of the same batch
CREATE INDEX IF NOT EXISTS backup_codes_batch_id_idx ON backup_codes(batch_id);

-- Index on the date of use for audit
CREATE INDEX IF NOT EXISTS backup_codes_used_at_idx ON backup_codes(used_at);

-- Index on the last_used_at (nouveau)
CREATE INDEX IF NOT EXISTS backup_codes_last_used_at_idx ON backup_codes(last_used_at);

-- Composite index for lots' management by date
CREATE INDEX IF NOT EXISTS backup_codes_user_batch_created_idx ON backup_codes(user_id, batch_id, created_at);

-- Index for security analyses
CREATE INDEX IF NOT EXISTS backup_codes_created_used_idx ON backup_codes(created_at, used);

-- Index for Lot Administration (batch + index)
CREATE INDEX IF NOT EXISTS backup_codes_batch_index_idx ON backup_codes(batch_id, code_index);

-- Indexes pour nouvelles colonnes
CREATE INDEX IF NOT EXISTS backup_codes_mfa_method_id_idx ON backup_codes(mfa_method_id);
CREATE INDEX IF NOT EXISTS backup_codes_code_idx ON backup_codes(code);

-- Option: contrainte FK vers table des méthodes MFA
-- ALTER TABLE backup_codes
--     ADD CONSTRAINT backup_codes_mfa_method_id_fkey FOREIGN KEY (mfa_method_id) REFERENCES mfa_methods(id) ON DELETE SET NULL;
-- CREATE INDEX backup_codes_batch_index_idx ON backup_codes(batch_id, code_index);