-- Migration 0018: Fix oauth_authorizations unique constraint
--
-- Problem: The current UNIQUE constraint on (bunker_public_key, tenant_id) prevents
-- users from having multiple OAuth authorizations for different apps when using
-- their own key as the bunker key (personal auth pattern).
--
-- Solution: Drop the bunker_public_key unique constraint and rely on the existing
-- oauth_auth_user_app_unique constraint (user_public_key, application_id) which
-- correctly allows one authorization per user per app.

-- Drop the problematic unique index
DROP INDEX IF EXISTS idx_oauth_authorizations_bunker_public_key_tenant;

-- Create a regular (non-unique) index for query performance
CREATE INDEX IF NOT EXISTS idx_oauth_authorizations_bunker_tenant
ON oauth_authorizations(bunker_public_key, tenant_id);
