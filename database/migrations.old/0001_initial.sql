-- ================ TRIGGER FUNCTION FOR AUTO-UPDATING updated_at ================

CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';


-- ================ USERS ================

CREATE TABLE users (
    public_key CHAR(64) PRIMARY KEY, -- hex
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TRIGGER users_update_trigger
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();


-- ================ TEAMS ================

CREATE TABLE teams (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TRIGGER teams_update_trigger
BEFORE UPDATE ON teams
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();


-- ================ TEAM USERS ================

CREATE TABLE team_users (
    id SERIAL PRIMARY KEY,
    team_id INTEGER REFERENCES teams(id),
    user_public_key CHAR(64) REFERENCES users(public_key),
    role TEXT NOT NULL CHECK (role IN ('admin', 'member')),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TRIGGER team_users_update_trigger
BEFORE UPDATE ON team_users
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();


-- ================ STORED KEYS ================

CREATE TABLE stored_keys (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    team_id INTEGER REFERENCES teams(id),
    public_key CHAR(64) NOT NULL, -- hex
    secret_key BYTEA NOT NULL, -- encrypted secret key
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TRIGGER stored_keys_update_trigger
BEFORE UPDATE ON stored_keys
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();


-- ================ POLICIES ================

CREATE TABLE policies (
    id SERIAL PRIMARY KEY,
    name TEXT NOT NULL,
    team_id INTEGER REFERENCES teams(id),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TRIGGER policies_update_trigger
BEFORE UPDATE ON policies
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();


-- ================ PERMISSIONS ================

CREATE TABLE permissions (
    id SERIAL PRIMARY KEY,
    identifier TEXT NOT NULL,
    config TEXT NOT NULL, -- json
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TRIGGER permissions_update_trigger
BEFORE UPDATE ON permissions
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();


-- ================ POLICY PERMISSIONS ================

CREATE TABLE policy_permissions (
    id SERIAL PRIMARY KEY,
    policy_id INTEGER REFERENCES policies(id),
    permission_id INTEGER REFERENCES permissions(id),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TRIGGER policy_permissions_update_trigger
BEFORE UPDATE ON policy_permissions
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();


-- ================ AUTHORIZATIONS ================

CREATE TABLE authorizations (
    id SERIAL PRIMARY KEY,
    stored_key_id INTEGER REFERENCES stored_keys(id),
    secret TEXT NOT NULL, -- secret connection uuid
    bunker_public_key CHAR(64) NOT NULL, -- hex
    bunker_secret BYTEA NOT NULL, -- encrypted bunker secret key
    relays TEXT NOT NULL, -- array of relays
    policy_id INTEGER REFERENCES policies(id),
    max_uses INTEGER,
    expires_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TRIGGER authorizations_update_trigger
BEFORE UPDATE ON authorizations
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();


-- ================ USER AUTHORIZATIONS ================

CREATE TABLE user_authorizations (
    id SERIAL PRIMARY KEY,
    user_public_key CHAR(64) REFERENCES users(public_key),
    authorization_id INTEGER REFERENCES authorizations(id),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT NOW()
);

CREATE TRIGGER user_authorizations_update_trigger
BEFORE UPDATE ON user_authorizations
FOR EACH ROW
EXECUTE FUNCTION update_updated_at_column();


-- ================ INDEXES ================

CREATE INDEX stored_keys_public_key_idx ON stored_keys (public_key);
CREATE INDEX stored_keys_team_id_idx ON stored_keys (team_id);

CREATE INDEX authorizations_stored_key_id_idx ON authorizations (stored_key_id);
CREATE UNIQUE INDEX authorizations_secret_idx ON authorizations (secret);

CREATE INDEX user_authorizations_user_public_key_idx ON user_authorizations (user_public_key);
CREATE INDEX user_authorizations_authorization_id_idx ON user_authorizations (authorization_id);
CREATE UNIQUE INDEX user_authorizations_user_public_key_authorization_id_idx ON user_authorizations (user_public_key, authorization_id);

CREATE UNIQUE INDEX users_public_key_idx ON users (public_key);

CREATE INDEX teams_name_idx ON teams (name);

CREATE INDEX team_users_team_id_idx ON team_users (team_id);
CREATE INDEX team_users_user_public_key_idx ON team_users (user_public_key);
CREATE UNIQUE INDEX team_users_team_id_user_public_key_idx ON team_users (team_id, user_public_key);

CREATE INDEX policies_name_idx ON policies (name);
CREATE INDEX policies_team_id_idx ON policies (team_id);

CREATE INDEX permissions_identifier_idx ON permissions (identifier);

CREATE INDEX policy_permissions_policy_id_idx ON policy_permissions (policy_id);
CREATE INDEX policy_permissions_permission_id_idx ON policy_permissions (permission_id);
CREATE UNIQUE INDEX policy_permissions_policy_id_permission_id_idx ON policy_permissions (policy_id, permission_id);
