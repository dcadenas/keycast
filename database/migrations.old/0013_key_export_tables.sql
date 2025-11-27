-- Migration: Add tables for secure key export flow
-- Tables for password+email 2FA verification before exporting private keys

-- Table for email verification codes sent during key export requests
CREATE TABLE IF NOT EXISTS key_export_codes (
    id SERIAL PRIMARY KEY,
    user_public_key CHAR(64) NOT NULL REFERENCES users(public_key) ON DELETE CASCADE,
    code TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    used_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_key_export_codes_user ON key_export_codes(user_public_key);
CREATE INDEX idx_key_export_codes_expires ON key_export_codes(expires_at);

-- Table for temporary export tokens (valid for 5 minutes after email verification)
CREATE TABLE IF NOT EXISTS key_export_tokens (
    id SERIAL PRIMARY KEY,
    user_public_key CHAR(64) NOT NULL REFERENCES users(public_key) ON DELETE CASCADE,
    token TEXT NOT NULL UNIQUE,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    used_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_key_export_tokens_user ON key_export_tokens(user_public_key);
CREATE INDEX idx_key_export_tokens_token ON key_export_tokens(token);
CREATE INDEX idx_key_export_tokens_expires ON key_export_tokens(expires_at);

-- Audit log for key exports (security tracking)
CREATE TABLE IF NOT EXISTS key_export_log (
    id SERIAL PRIMARY KEY,
    user_public_key CHAR(64) NOT NULL REFERENCES users(public_key) ON DELETE CASCADE,
    format TEXT NOT NULL,  -- 'nsec', 'ncryptsec', or 'mnemonic'
    exported_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_key_export_log_user ON key_export_log(user_public_key);
CREATE INDEX idx_key_export_log_exported_at ON key_export_log(exported_at);
