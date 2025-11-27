-- Personal authentication for Keycast
-- This migration adds support for email/password authentication and personal Nostr keys

-- Add email and password columns to users table
ALTER TABLE users ADD COLUMN email TEXT;
ALTER TABLE users ADD COLUMN password_hash TEXT;

-- Create unique index on email for faster lookups and uniqueness
CREATE UNIQUE INDEX idx_users_email ON users(email) WHERE email IS NOT NULL;

-- Create personal_keys table to store user's own Nostr keys (encrypted)
CREATE TABLE personal_keys (
    id SERIAL PRIMARY KEY,
    user_public_key CHAR(64) NOT NULL REFERENCES users(public_key) ON DELETE CASCADE,
    encrypted_secret_key BYTEA NOT NULL,
    bunker_secret TEXT NOT NULL UNIQUE,  -- NIP-46 connection secret
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_personal_keys_user_public_key ON personal_keys(user_public_key);
CREATE INDEX idx_personal_keys_bunker_secret ON personal_keys(bunker_secret);

CREATE TRIGGER personal_keys_update_trigger
BEFORE UPDATE ON personal_keys
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();
