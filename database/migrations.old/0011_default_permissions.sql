-- ABOUTME: Seed default permission templates and create default policy for keycast-login
-- ABOUTME: Provides sensible permission defaults for personal signing (social + messaging, no financial)

-- ================ ADD POLICY_ID TO OAUTH_APPLICATIONS ================
-- OAuth applications need to specify which policy they use
ALTER TABLE oauth_applications ADD COLUMN IF NOT EXISTS policy_id INTEGER REFERENCES policies(id);
CREATE INDEX IF NOT EXISTS idx_oauth_applications_policy_id ON oauth_applications(policy_id);

-- ================ DEFAULT PERMISSION TEMPLATES ================
-- These permissions can be reused across multiple policies

-- Permission 1: Social Events Only (kinds 0, 1, 3, 7, 9735)
-- Allows: Profile, Notes, Follows, Reactions, Zap receipts
-- Safe for basic social clients
INSERT INTO permissions (identifier, config, created_at, updated_at)
VALUES (
    'allowed_kinds_social',
    '{"allowed_kinds": [0, 1, 3, 7, 9735]}',
    NOW(),
    NOW()
)
ON CONFLICT DO NOTHING;

-- Permission 2: Messaging (kinds 4, 44, 1059)
-- Allows: Encrypted DMs (NIP-04, NIP-44), Gift wraps
-- Sensitive: gives access to private messages
INSERT INTO permissions (identifier, config, created_at, updated_at)
VALUES (
    'allowed_kinds_messaging',
    '{"allowed_kinds": [4, 44, 1059]}',
    NOW(),
    NOW()
)
ON CONFLICT DO NOTHING;

-- Permission 3: Zaps Only (kind 9734)
-- Allows: Zap requests (spending money!)
-- Financial: should require explicit approval
INSERT INTO permissions (identifier, config, created_at, updated_at)
VALUES (
    'allowed_kinds_zaps',
    '{"allowed_kinds": [9734]}',
    NOW(),
    NOW()
)
ON CONFLICT DO NOTHING;

-- Permission 4: Lists & Data (kinds 10000-19999)
-- Allows: Mute lists, pin lists, bookmarks, etc.
-- Generally safe, user-specific data
INSERT INTO permissions (identifier, config, created_at, updated_at)
VALUES (
    'allowed_kinds_lists',
    '{"allowed_kinds": [10000, 10001, 10002, 10003, 10004, 10005, 10006, 10007, 10015, 10030]}',
    NOW(),
    NOW()
)
ON CONFLICT DO NOTHING;

-- Permission 5: Long-form Content (kinds 30000-39999)
-- Allows: Long-form articles, blogs, etc.
-- Generally safe for content creation
INSERT INTO permissions (identifier, config, created_at, updated_at)
VALUES (
    'allowed_kinds_longform',
    '{"allowed_kinds": [30023, 30024, 30030, 30040, 30041, 30078, 30311, 30315, 30402, 30403]}',
    NOW(),
    NOW()
)
ON CONFLICT DO NOTHING;

-- Permission 6: Wallet Operations (kinds 23194, 23195)
-- Allows: Wallet connect, wallet operations
-- DANGEROUS: direct wallet access
INSERT INTO permissions (identifier, config, created_at, updated_at)
VALUES (
    'allowed_kinds_wallet',
    '{"allowed_kinds": [23194, 23195]}',
    NOW(),
    NOW()
)
ON CONFLICT DO NOTHING;

-- Permission 7: Deletion Events (kind 5)
-- Allows: Deleting events
-- DANGEROUS: can delete all user content
INSERT INTO permissions (identifier, config, created_at, updated_at)
VALUES (
    'allowed_kinds_deletion',
    '{"allowed_kinds": [5]}',
    NOW(),
    NOW()
)
ON CONFLICT DO NOTHING;

-- Permission 8: Reports (kind 1984)
-- Allows: Filing reports/complaints
-- Sensitive: can be abused for harassment
INSERT INTO permissions (identifier, config, created_at, updated_at)
VALUES (
    'allowed_kinds_reports',
    '{"allowed_kinds": [1984]}',
    NOW(),
    NOW()
)
ON CONFLICT DO NOTHING;

-- Permission 9: All Social + Messaging (common safe bundle)
-- Combines social events + messaging for convenience
-- Does NOT include financial, deletion, or dangerous operations
INSERT INTO permissions (identifier, config, created_at, updated_at)
VALUES (
    'allowed_kinds_social_messaging',
    '{"allowed_kinds": [0, 1, 3, 4, 7, 44, 1059, 9735]}',
    NOW(),
    NOW()
)
ON CONFLICT DO NOTHING;

-- ================ DEFAULT POLICIES ================
-- Policy templates that can be cloned for new users

-- Policy 1: "Standard Social" (DEFAULT for keycast-login)
-- Recommended for most users: Social + Messaging, no financial/dangerous ops
-- This gets assigned to new users on registration
INSERT INTO policies (name, team_id, created_at, updated_at, tenant_id)
VALUES (
    'Standard Social (Default)',
    NULL,  -- Not team-specific
    NOW(),
    NOW(),
    1  -- Default tenant
)
ON CONFLICT DO NOTHING;

-- Link Permission 9 (All Social + Messaging) to Policy 1
INSERT INTO policy_permissions (policy_id, permission_id, created_at, updated_at)
SELECT
    p.id,
    perm.id,
    NOW(),
    NOW()
FROM policies p
CROSS JOIN permissions perm
WHERE p.name = 'Standard Social (Default)'
  AND p.tenant_id = 1
  AND perm.identifier = 'allowed_kinds_social_messaging'
  AND NOT EXISTS (
    SELECT 1 FROM policy_permissions pp
    WHERE pp.policy_id = p.id AND pp.permission_id = perm.id
  );

-- Policy 2: "Read Only"
-- For browse-only clients, no posting
-- Just reactions and follows, no content creation
INSERT INTO policies (name, team_id, created_at, updated_at, tenant_id)
VALUES (
    'Read Only',
    NULL,
    NOW(),
    NOW(),
    1  -- Default tenant
)
ON CONFLICT DO NOTHING;

INSERT INTO policy_permissions (policy_id, permission_id, created_at, updated_at)
SELECT
    p.id,
    perm.id,
    NOW(),
    NOW()
FROM policies p
CROSS JOIN permissions perm
WHERE p.name = 'Read Only'
  AND p.tenant_id = 1
  AND perm.identifier = 'allowed_kinds_social'
  AND NOT EXISTS (
    SELECT 1 FROM policy_permissions pp
    WHERE pp.policy_id = p.id AND pp.permission_id = perm.id
  );

-- Policy 3: "Wallet Only"
-- For zap wallets, only allow zap requests
-- No social or messaging capabilities
INSERT INTO policies (name, team_id, created_at, updated_at, tenant_id)
VALUES (
    'Wallet Only',
    NULL,
    NOW(),
    NOW(),
    1  -- Default tenant
)
ON CONFLICT DO NOTHING;

INSERT INTO policy_permissions (policy_id, permission_id, created_at, updated_at)
SELECT
    p.id,
    perm.id,
    NOW(),
    NOW()
FROM policies p
CROSS JOIN permissions perm
WHERE p.name = 'Wallet Only'
  AND p.tenant_id = 1
  AND perm.identifier = 'allowed_kinds_zaps'
  AND NOT EXISTS (
    SELECT 1 FROM policy_permissions pp
    WHERE pp.policy_id = p.id AND pp.permission_id = perm.id
  );

-- ================ CREATE DEFAULT OAUTH APPLICATION ================
-- The "keycast-login" OAuth application for personal HTTP signing

-- First, create or update the keycast-login OAuth application
-- This app uses the "Standard Social (Default)" policy
INSERT INTO oauth_applications (
    client_id,
    client_secret,
    name,
    redirect_uris,
    policy_id,
    tenant_id,
    created_at,
    updated_at
)
VALUES (
    'keycast-login',
    'not-used-for-personal-auth',  -- Personal auth uses JWT, not OAuth client secret
    'Personal Keycast Bunker',
    'http://localhost:3000/api/connect,https://login.divine.video/api/connect',
    (SELECT id FROM policies WHERE name = 'Standard Social (Default)' AND tenant_id = 1 LIMIT 1),
    1,  -- Default tenant
    NOW(),
    NOW()
)
ON CONFLICT (tenant_id, client_id)
DO UPDATE SET
    client_secret = EXCLUDED.client_secret,
    name = EXCLUDED.name,
    redirect_uris = EXCLUDED.redirect_uris,
    policy_id = EXCLUDED.policy_id,
    updated_at = NOW();

-- ================ NOTES ================
-- When a new user registers:
-- 1. Create oauth_authorization linking user to keycast-login app
-- 2. The authorization inherits the policy_id from oauth_applications
-- 3. HTTP signing validates against this policy's permissions
-- 4. Users can later customize their permissions via UI

-- Event Kind Reference:
-- 0: Profile metadata
-- 1: Short text note
-- 3: Follow list
-- 4: Encrypted DM (NIP-04)
-- 5: Deletion
-- 7: Reaction
-- 44: Encrypted DM (NIP-44)
-- 1059: Gift wrap
-- 1984: Reporting
-- 9734: Zap request
-- 9735: Zap receipt
-- 10000+: Replaceable events (lists)
-- 23194-23195: Wallet operations
-- 30000+: Parameterized replaceable (long-form, etc.)
