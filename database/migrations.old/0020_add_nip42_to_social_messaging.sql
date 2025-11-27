-- Add kind 22242 (NIP-42 relay authentication) to allowed_kinds_social_messaging permission
-- This allows OAuth clients to authenticate with relays

UPDATE permissions
SET config = '{"allowed_kinds": [0, 1, 3, 4, 7, 44, 1059, 9735, 22242]}'::jsonb,
    updated_at = NOW()
WHERE identifier = 'allowed_kinds_social_messaging';
