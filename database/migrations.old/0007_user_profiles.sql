-- User profiles table for storing kind 0 metadata
-- Stores the user's Nostr profile (name, about, picture, etc.)

CREATE TABLE IF NOT EXISTS user_profiles (
    public_key CHAR(64) PRIMARY KEY REFERENCES users(public_key) ON DELETE CASCADE,
    profile_json TEXT NOT NULL,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_user_profiles_updated_at ON user_profiles(updated_at);
