-- ABOUTME: Add multi-tenancy support with domain-based tenant isolation
-- ABOUTME: Each tenant (domain) gets isolated user pools, OAuth apps, and data

-- ================ TENANTS TABLE ================
-- Central registry of all tenants (domains) in the system
CREATE TABLE IF NOT EXISTS tenants (
    id BIGSERIAL PRIMARY KEY,
    domain TEXT NOT NULL UNIQUE,  -- e.g. "holis.social", "divine.video"
    name TEXT NOT NULL,            -- Display name for the tenant
    settings TEXT,                 -- JSON config: branding, relay URLs, email config, etc
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_tenants_domain ON tenants(domain);
CREATE INDEX idx_tenants_name ON tenants(name);

CREATE TRIGGER tenants_update_trigger
BEFORE UPDATE ON tenants
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();

-- ================ ADD TENANT_ID TO EXISTING TABLES ================
-- Default to 1 (existing data becomes first tenant)

-- Users table (email and username must be unique per tenant)
ALTER TABLE users ADD COLUMN tenant_id BIGINT NOT NULL DEFAULT 1 REFERENCES tenants(id);
CREATE INDEX idx_users_tenant_id ON users(tenant_id);

-- Teams table
ALTER TABLE teams ADD COLUMN tenant_id BIGINT NOT NULL DEFAULT 1 REFERENCES tenants(id);
CREATE INDEX idx_teams_tenant_id ON teams(tenant_id);

-- Stored keys table
ALTER TABLE stored_keys ADD COLUMN tenant_id BIGINT NOT NULL DEFAULT 1 REFERENCES tenants(id);
CREATE INDEX idx_stored_keys_tenant_id ON stored_keys(tenant_id);

-- Policies table
ALTER TABLE policies ADD COLUMN tenant_id BIGINT NOT NULL DEFAULT 1 REFERENCES tenants(id);
CREATE INDEX idx_policies_tenant_id ON policies(tenant_id);

-- Authorizations table (bunker_public_key must be unique per tenant)
ALTER TABLE authorizations ADD COLUMN tenant_id BIGINT NOT NULL DEFAULT 1 REFERENCES tenants(id);
CREATE INDEX idx_authorizations_tenant_id ON authorizations(tenant_id);

-- Personal keys table (bunker_secret must be unique per tenant)
ALTER TABLE personal_keys ADD COLUMN tenant_id BIGINT NOT NULL DEFAULT 1 REFERENCES tenants(id);
CREATE INDEX idx_personal_keys_tenant_id ON personal_keys(tenant_id);

-- OAuth applications table (client_id must be unique per tenant)
-- PostgreSQL: Just add the column, no need to recreate table
ALTER TABLE oauth_applications ADD COLUMN tenant_id BIGINT NOT NULL DEFAULT 1 REFERENCES tenants(id);
CREATE INDEX idx_oauth_applications_tenant_id ON oauth_applications(tenant_id);

-- OAuth codes table
ALTER TABLE oauth_codes ADD COLUMN tenant_id BIGINT NOT NULL DEFAULT 1 REFERENCES tenants(id);
CREATE INDEX idx_oauth_codes_tenant_id ON oauth_codes(tenant_id);

-- OAuth authorizations table
ALTER TABLE oauth_authorizations ADD COLUMN tenant_id BIGINT NOT NULL DEFAULT 1 REFERENCES tenants(id);
CREATE INDEX idx_oauth_authorizations_tenant_id ON oauth_authorizations(tenant_id);

-- Signing activity table
ALTER TABLE signing_activity ADD COLUMN tenant_id BIGINT NOT NULL DEFAULT 1 REFERENCES tenants(id);
CREATE INDEX idx_signing_activity_tenant_id ON signing_activity(tenant_id);

-- ================ UPDATE UNIQUE CONSTRAINTS ================
-- Drop old global unique constraints and replace with tenant-scoped ones

-- Users: email must be unique per tenant
DROP INDEX IF EXISTS idx_users_email;
CREATE UNIQUE INDEX idx_users_email_tenant ON users(tenant_id, email) WHERE email IS NOT NULL;

-- Users: username must be unique per tenant (for NIP-05)
DROP INDEX IF EXISTS idx_users_username;
CREATE UNIQUE INDEX idx_users_username_tenant ON users(tenant_id, username) WHERE username IS NOT NULL;

-- OAuth applications: client_id must be unique per tenant
CREATE UNIQUE INDEX idx_oauth_applications_client_id_tenant ON oauth_applications(tenant_id, client_id);

-- Authorizations: secret unique per tenant
DROP INDEX IF EXISTS authorizations_secret_idx;
CREATE UNIQUE INDEX idx_authorizations_secret_tenant ON authorizations(tenant_id, secret);

-- Personal keys: bunker_secret unique per tenant
-- Drop the UNIQUE constraint (not just the index)
ALTER TABLE personal_keys DROP CONSTRAINT IF EXISTS personal_keys_bunker_secret_key;
DROP INDEX IF EXISTS idx_personal_keys_bunker_secret;
CREATE UNIQUE INDEX idx_personal_keys_bunker_secret_tenant ON personal_keys(tenant_id, bunker_secret);

-- OAuth authorizations: bunker_public_key unique per tenant
-- Drop the UNIQUE constraint if it still exists (migration 0005 should have removed it)
ALTER TABLE oauth_authorizations DROP CONSTRAINT IF EXISTS oauth_authorizations_bunker_public_key_key;
DROP INDEX IF EXISTS oauth_authorizations_bunker_public_key_key;
CREATE UNIQUE INDEX idx_oauth_authorizations_bunker_public_key_tenant ON oauth_authorizations(tenant_id, bunker_public_key);

-- ================ INSERT DEFAULT TENANT ================
-- Create tenant for existing login.divine.video deployment
INSERT INTO tenants (id, domain, name, settings, created_at, updated_at)
VALUES (
    1,
    'login.divine.video',
    'Divine Video',
    '{"relay":"wss://relay.damus.io","email_from":"noreply@divine.video"}',
    NOW(),
    NOW()
);
