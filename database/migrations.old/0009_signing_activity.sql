-- ABOUTME: Tracks all signing activity for each user/app bunker connection
-- ABOUTME: Records what events were signed, when, and by which app

CREATE TABLE IF NOT EXISTS signing_activity (
    id SERIAL PRIMARY KEY,
    user_public_key CHAR(64) NOT NULL REFERENCES users(public_key) ON DELETE CASCADE,
    application_id INTEGER REFERENCES oauth_applications(id) ON DELETE SET NULL,
    bunker_secret TEXT NOT NULL,
    event_kind INTEGER NOT NULL,
    event_content TEXT,
    event_id CHAR(64),
    client_public_key CHAR(64),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_signing_activity_user ON signing_activity(user_public_key);
CREATE INDEX idx_signing_activity_app ON signing_activity(application_id);
CREATE INDEX idx_signing_activity_bunker_secret ON signing_activity(bunker_secret);
CREATE INDEX idx_signing_activity_created_at ON signing_activity(created_at);
