-- Fix OAuth authorizations UNIQUE constraint
-- Since we now use the user's personal key as bunker_public_key,
-- multiple authorizations per user will have the same bunker_public_key
-- but different application_ids. Change UNIQUE constraint accordingly.

-- Drop the old unique constraint on bunker_public_key
ALTER TABLE oauth_authorizations DROP CONSTRAINT IF EXISTS oauth_authorizations_bunker_public_key_key;

-- Add policy_id, expires_at, and revoked_at columns if they don't exist
ALTER TABLE oauth_authorizations ADD COLUMN IF NOT EXISTS policy_id INTEGER;
ALTER TABLE oauth_authorizations ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE oauth_authorizations ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMP WITH TIME ZONE;

-- Add unique constraint on (user_public_key, application_id) combination
ALTER TABLE oauth_authorizations ADD CONSTRAINT oauth_auth_user_app_unique
    UNIQUE(user_public_key, application_id);
