-- ABOUTME: Add PKCE (Proof Key for Code Exchange) support to OAuth authorization code flow
-- ABOUTME: Implements RFC 7636 security extension to prevent authorization code interception attacks

-- Add PKCE fields to oauth_codes table
ALTER TABLE oauth_codes
ADD COLUMN code_challenge TEXT,
ADD COLUMN code_challenge_method TEXT;

-- Add index for potential cleanup/monitoring queries
CREATE INDEX IF NOT EXISTS idx_oauth_codes_challenge ON oauth_codes(code_challenge)
WHERE code_challenge IS NOT NULL;

-- Note: Columns are nullable for backward compatibility
-- Existing OAuth flows without PKCE will continue to work
-- PKCE can be enforced per-tenant or application in future updates
