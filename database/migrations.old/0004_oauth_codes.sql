-- OAuth tables for authorization code flow

-- oauth_applications: third-party apps that can request OAuth authorization
CREATE TABLE IF NOT EXISTS oauth_applications (
    id SERIAL PRIMARY KEY,
    client_id TEXT NOT NULL UNIQUE,
    client_secret TEXT NOT NULL,
    name TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,  -- JSON array of allowed redirect URIs
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TRIGGER oauth_applications_update_trigger
BEFORE UPDATE ON oauth_applications
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

-- oauth_codes: authorization codes (short-lived, one-time use)
CREATE TABLE IF NOT EXISTS oauth_codes (
    code TEXT PRIMARY KEY NOT NULL,
    user_public_key CHAR(64) NOT NULL REFERENCES users(public_key),
    application_id INTEGER NOT NULL REFERENCES oauth_applications(id),
    redirect_uri TEXT NOT NULL,
    scope TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

-- oauth_authorizations: long-lived authorizations with their own keys
CREATE TABLE IF NOT EXISTS oauth_authorizations (
    id SERIAL PRIMARY KEY,
    user_public_key CHAR(64) NOT NULL REFERENCES users(public_key),
    application_id INTEGER NOT NULL REFERENCES oauth_applications(id),
    bunker_public_key CHAR(64) NOT NULL UNIQUE,
    bunker_secret BYTEA NOT NULL,
    secret TEXT NOT NULL,  -- Connection secret for NIP-46
    relays TEXT NOT NULL,  -- Relay URL for NIP-46
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TRIGGER oauth_authorizations_update_trigger
BEFORE UPDATE ON oauth_authorizations
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

-- Indexes
CREATE INDEX IF NOT EXISTS idx_oauth_codes_expires ON oauth_codes(expires_at);
CREATE INDEX IF NOT EXISTS idx_oauth_codes_user ON oauth_codes(user_public_key);
CREATE INDEX IF NOT EXISTS idx_oauth_auth_user ON oauth_authorizations(user_public_key);
CREATE INDEX IF NOT EXISTS idx_oauth_auth_app ON oauth_authorizations(application_id);
