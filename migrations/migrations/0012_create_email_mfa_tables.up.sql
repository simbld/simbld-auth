-- sql
-- migrations/0009_create_email_mfa_tables.up.sql
-- Création des tables pour Email MFA : email_mfa_codes et email_mfa_settings
-- Ajout d'indices utiles et d'un trigger pour maintenir updated_at

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Table des codes d'authentification par email
CREATE TABLE IF NOT EXISTS email_mfa_codes
(
    id         UUID PRIMARY KEY                  DEFAULT gen_random_uuid(),
    -- haché du code (ne jamais stocker le code en clair)
    code_hash  VARCHAR(255)             NOT NULL,
    -- adresse email utilisée (utile si pas de liaison user ou pour audits)
    email      VARCHAR(255)             NOT NULL,
    -- optionnel : lier au user si besoin
    user_id    UUID REFERENCES users (id) ON DELETE CASCADE,
    -- date de création et d'expiration
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    -- utilisation / audit
    used       BOOLEAN                  NOT NULL DEFAULT FALSE,
    used_at    TIMESTAMP WITH TIME ZONE,
    -- champs optionnels pour lot / indexation
    batch_id   UUID,
    code_index INTEGER
);

CREATE INDEX IF NOT EXISTS email_mfa_codes_email_idx ON email_mfa_codes (email);
CREATE INDEX IF NOT EXISTS email_mfa_codes_user_id_idx ON email_mfa_codes (user_id);
CREATE INDEX IF NOT EXISTS email_mfa_codes_email_used_idx ON email_mfa_codes (email, used);
CREATE INDEX IF NOT EXISTS email_mfa_codes_expires_at_idx ON email_mfa_codes (expires_at);

-- Table des paramètres Email MFA par utilisateur
CREATE TABLE IF NOT EXISTS email_mfa_settings
(
    user_id    UUID PRIMARY KEY REFERENCES users (id) ON DELETE CASCADE,
    email      VARCHAR(255)             NOT NULL,
    enabled    BOOLEAN                  NOT NULL DEFAULT TRUE,
    verified   BOOLEAN                  NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS email_mfa_settings_email_idx ON email_mfa_settings (email);

-- Trigger utilitaire pour maintenir updated_at à jour sur update
CREATE OR REPLACE FUNCTION mfa_set_updated_at()
    RETURNS TRIGGER AS
$$
BEGIN
    NEW.updated_at = CURRENT_TIMESTAMP;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_email_mfa_settings_updated_at ON email_mfa_settings;
CREATE TRIGGER trg_email_mfa_settings_updated_at
    BEFORE UPDATE
    ON email_mfa_settings
    FOR EACH ROW
EXECUTE PROCEDURE mfa_set_updated_at();

-- (Optionnel) si vous voulez aussi mettre à jour updated_at sur d'autres tables,
-- vous pouvez créer des triggers similaires.
