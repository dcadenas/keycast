-- Add username field for NIP-05 identifiers
-- Users can choose their own username for name@domain.com format

ALTER TABLE users ADD COLUMN username TEXT;

CREATE UNIQUE INDEX idx_users_username ON users(username) WHERE username IS NOT NULL;
