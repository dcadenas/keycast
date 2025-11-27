-- Make bunker_secret nullable since we removed auto-bunker creation
-- Users create bunker connections manually via /user/bunker/create

ALTER TABLE personal_keys ALTER COLUMN bunker_secret DROP NOT NULL;

-- Drop unique constraint since it's no longer used
DROP INDEX IF EXISTS idx_personal_keys_bunker_secret_tenant;

-- Add comment explaining the column is deprecated
COMMENT ON COLUMN personal_keys.bunker_secret IS 'Deprecated: Was used for auto-bunker creation. Now bunker connections are created manually via oauth_authorizations.';
