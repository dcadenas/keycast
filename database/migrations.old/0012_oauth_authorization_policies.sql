-- ABOUTME: Add policy_id to oauth_authorizations for per-user, per-app permission customization
-- ABOUTME: Allows users to grant different permissions to the same app based on requested OAuth scopes

-- Add policy_id column to oauth_authorizations
-- Allows each authorization to have its own policy (customized based on requested scopes)
-- Falls back to the application's default policy if not set
ALTER TABLE oauth_authorizations ADD COLUMN IF NOT EXISTS policy_id INTEGER REFERENCES policies(id);

-- Create index for faster policy lookups during signing
CREATE INDEX IF NOT EXISTS idx_oauth_authorizations_policy_id ON oauth_authorizations(policy_id);

-- For existing authorizations, inherit policy from their applications
-- This ensures backward compatibility
UPDATE oauth_authorizations
SET policy_id = (
    SELECT policy_id
    FROM oauth_applications
    WHERE oauth_applications.id = oauth_authorizations.application_id
)
WHERE policy_id IS NULL;
