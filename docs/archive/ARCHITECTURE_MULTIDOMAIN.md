# Keycast Multi-Domain Architecture Summary

> ⚠️ **DEPRECATED** - This document describes an outdated single-domain architecture.
> The current system uses docker-compose with PostgreSQL persistent volumes.
> See `/docs/ARCHITECTURE.md` and `/CLAUDE.md` for current architecture.

## Overview
Keycast is a NIP-46 remote signing service with OAuth 2.0 authorization, built in Rust using Axum web framework and PostgreSQL. It enables users to sign into Nostr apps using email/password authentication with encrypted key management.

**Current Deployment**: Single domain (login.divine.video) on Google Cloud Run with Litestream for PostgreSQL persistence.

---

## 1. WEB SERVER CONFIGURATION

### Framework & Architecture
- **Framework**: Axum 0.7 (Rust async HTTP framework)
- **Database**: PostgreSQL with SQLx ORM
- **Server**: Runs on Cloud Run, binds to 0.0.0.0 on port 8080 (via PORT env var)
- **Process**: Single unified process serving API + static files

### Static File Serving
**Location**: `/Users/rabble/code/andotherstuff/keycast/api/src/main.rs:120-170`

- `/examples/` → Serves example HTML clients from `/examples` directory
- `/` → Serves public HTML files from `/public` directory
  - `login.html` → `/login`
  - `register.html` → `/register`
  - `dashboard.html` → `/dashboard`
  - `profile.html` → `/profile`
- `/.well-known/nostr.json` → NIP-05 discovery endpoint

### Routing Structure
**Location**: `/Users/rabble/code/andotherstuff/keycast/api/src/api/http/routes.rs`

Routes are organized into logical groups:

1. **Public Auth Routes** (no authentication)
   - `POST /api/auth/register` → Create account with email/password
   - `POST /api/auth/login` → Authenticate and get JWT
   - `POST /api/auth/verify-email` → Verify email with token
   - `POST /api/auth/forgot-password` → Request password reset
   - `POST /api/auth/reset-password` → Reset password with token

2. **OAuth Routes** (no authentication required initially)
   - `GET /api/oauth/authorize` → Start OAuth flow (shows approval page)
   - `POST /api/oauth/authorize` → User approves/denies, gets code
   - `POST /api/oauth/token` → Exchange code for bunker URL
   - `POST /api/oauth/connect` → nostr-login integration
   - `GET /api/connect/*nostrconnect` → nostr-login URI handler

3. **Protected User Routes** (JWT authentication required)
   - `GET /api/user/bunker` → Get personal NIP-46 bunker URL
   - `GET /api/user/profile` → Get username (only server-side data)
   - `GET /api/user/sessions` → List active sessions with activity
   - `GET /api/user/sessions/:secret/activity` → Activity log for session
   - `POST /api/user/profile` → Update username (NIP-05)
   - `POST /api/user/sessions/revoke` → Revoke a session

4. **Team Routes** (JWT authentication required)
   - CRUD operations for teams, users, keys, authorizations, policies

### CORS Configuration
**Location**: `/Users/rabble/code/andotherstuff/keycast/api/src/main.rs:119-126`

```rust
let cors = CorsLayer::new()
    .allow_origin(Any)
    .allow_methods(Any)
    .allow_headers(Any)
    .allow_credentials(false);
```

**Current State**: Permissive CORS allowing ALL origins (designed for embeddable OAuth flows)
- Any origin can make cross-origin requests
- No credentials sent with CORS requests
- All methods and headers allowed

---

## 2. AUTHENTICATION & USER SYSTEM

### User Registration Flow
**Location**: `/Users/rabble/code/andotherstuff/keycast/api/src/api/http/auth.rs:260-440`

1. User provides email + password
2. System generates new Nostr keypair
3. Secret key is encrypted with GCP KMS or local file key manager
4. Email verification token generated (24 hour expiry)
5. Personal OAuth application created for seamless access
6. JWT token returned for immediate login
7. Verification email sent (via SendGrid, optional)

**Database Involved**:
- `users` → stores email, password_hash, email_verified
- `personal_keys` → stores encrypted user secret key + bunker_secret
- `oauth_applications` → default 'keycast-login' app
- `oauth_authorizations` → personal bunker URL authorization

### Authentication Methods

#### 1. JWT Token (Bearer Token)
- **Type**: HS256 (symmetric)
- **Expiry**: 24 hours
- **Header Format**: `Authorization: Bearer <token>`
- **Claims**: 
  ```json
  {
    "sub": "user_public_key_hex",
    "exp": timestamp
  }
  ```

#### 2. NIP-98 Event Signature (Nostr HTTP Auth)
- **Type**: Nostr event with Kind 27235 (HttpAuth)
- **Header Format**: `Authorization: Nostr <base64_encoded_event_json>`
- **Validation**:
  - Event signature must be valid
  - Event must be Kind 27235 (HttpAuth)
  - Event must be less than 60 seconds old
  - `u` tag must match full request URL with scheme/host
  - `method` tag must match HTTP method

**Middleware**: `/Users/rabble/code/andotherstuff/keycast/api/src/api/http/mod.rs:28-197`

### User Data Model
**Location**: `database/migrations/0003_personal_auth.sql` + migrations

```sql
-- Core user table
CREATE TABLE users (
    public_key CHAR(64) PRIMARY KEY,      -- Nostr pubkey (hex)
    email TEXT,                            -- Email for login
    password_hash TEXT,                    -- Bcrypt hash
    email_verified BOOLEAN DEFAULT FALSE,
    email_verification_token TEXT,
    email_verification_expires_at DATETIME,
    password_reset_token TEXT,
    password_reset_expires_at DATETIME,
    username TEXT UNIQUE,                  -- For NIP-05 (name@domain)
    created_at DATETIME,
    updated_at DATETIME
);

-- Encrypted personal keys
CREATE TABLE personal_keys (
    id INTEGER PRIMARY KEY,
    user_public_key CHAR(64) REFERENCES users(public_key),
    encrypted_secret_key BLOB,             -- Encrypted with key manager
    bunker_secret TEXT UNIQUE,             -- NIP-46 connection secret
    created_at DATETIME,
    updated_at DATETIME
);
```

### No Server-Side Profile Storage
**Important**: Keycast only stores:
- Email (for login)
- Username (for NIP-05 only)
- Encrypted Nostr key

All other profile data (name, about, picture, etc.) is stored on Nostr relays as Kind 0 events via the bunker URL.

---

## 3. OAUTH 2.0 AUTHORIZATION FLOW

### Authorization Code Flow
**Location**: `/Users/rabble/code/andotherstuff/keycast/api/src/api/http/oauth.rs`

#### Flow Diagram:
```
1. Client requests: GET /api/oauth/authorize?client_id=...&redirect_uri=...
2. User logs in (JWT obtained)
3. User approves → POST /api/oauth/authorize
4. System creates authorization code (10 min expiry)
5. System returns code to client
6. Client exchanges code: POST /api/oauth/token
7. System creates NIP-46 bunker URL with connection secret
8. Client receives bunker:// URL
9. Client uses bunker URL to sign events via NIP-46
```

### OAuth Database Schema
**Location**: `database/migrations/0004_oauth_codes.sql`

```sql
CREATE TABLE oauth_applications (
    id INTEGER PRIMARY KEY,
    client_id TEXT NOT NULL UNIQUE,
    client_secret TEXT NOT NULL,
    name TEXT NOT NULL,
    redirect_uris TEXT,                    -- JSON array
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);

CREATE TABLE oauth_codes (
    code TEXT PRIMARY KEY,
    user_public_key TEXT REFERENCES users(public_key),
    application_id INTEGER REFERENCES oauth_applications(id),
    redirect_uri TEXT NOT NULL,
    scope TEXT,
    expires_at TIMESTAMP,                  -- 10 minute expiry
    created_at TIMESTAMP
);

CREATE TABLE oauth_authorizations (
    id INTEGER PRIMARY KEY,
    user_public_key TEXT REFERENCES users(public_key),
    application_id INTEGER REFERENCES oauth_applications(id),
    bunker_public_key TEXT UNIQUE,         -- User's Nostr pubkey
    bunker_secret BLOB,                    -- Encrypted user secret key
    secret TEXT,                           -- Connection secret (for NIP-46)
    client_public_key TEXT,                -- For nostr-login
    relays TEXT,                           -- JSON array of relay URLs
    revoked_at DATETIME,
    created_at TIMESTAMP,
    updated_at TIMESTAMP
);
```

### Key Observations for Multi-Domain
- **Application Registration**: Dynamic - apps are created on first authorization
- **Redirect URIs**: Stored as JSON, no validation on first auth
- **Bunker URLs**: Per-application per-user, includes relay URL
- **Connection Secrets**: Random 32-48 byte alphanumeric strings

---

## 4. DOMAIN & CORS HANDLING

### Current Configuration
**Single Domain Architecture**:
- API: `https://login.divine.video`
- All static HTML served from same domain
- All examples served from same domain

### Environment Variables
**Location**: `service.yaml` and `.env.production`

```yaml
CORS_ALLOWED_ORIGIN: https://login.divine.video
APP_URL: https://login.divine.video
FROM_EMAIL: noreply@divine.video
```

### NIP-05 Discovery
**Location**: `/Users/rabble/code/andotherstuff/keycast/api/src/api/http/routes.rs:166-217`

```
GET /.well-known/nostr.json?name=username
```

Returns:
```json
{
  "names": {
    "username": "public_key_hex"
  }
}
```

This enables `username@login.divine.video` NIP-05 identifiers.

### Hardcoded Domain References
- **Relay URL**: Hardcoded to `wss://relay.damus.io` in multiple places
- **Bunker URL Format**: `bunker://pubkey?relay=...&secret=...`
- **nostr-login endpoint**: `http://localhost:3000/api/connect/<nostrconnect>` (hardcoded in discovery)

---

## 5. DATABASE SCHEMA FOR MULTI-TENANCY

### Current Schema (Single-Tenant)
All tables assume single Keycast instance:

1. **users** → All users of THIS Keycast instance
2. **personal_keys** → One per user
3. **oauth_applications** → Apps authorized on THIS instance
4. **oauth_authorizations** → User grants access to apps on THIS instance
5. **oauth_codes** → Temporary authorization codes
6. **teams** → Optional team management (for enterprise)
7. **stored_keys** → Team-owned keys (distinct from personal keys)
8. **policies** → Authorization policies for team keys
9. **signing_activity** → Audit log of all signing events

### Multi-Tenancy Considerations

**To support multiple domains, would need:**
1. `tenant_id` field in all core tables (users, oauth_apps, authorizations)
2. Unique constraint on (tenant_id, email) instead of just email
3. Unique constraint on (tenant_id, username) for NIP-05
4. Isolated data access via tenant context middleware
5. Per-tenant NIP-05 discovery endpoints

**Current Constraints**:
- `email` has UNIQUE index globally (no multi-tenant isolation)
- `username` has UNIQUE index globally
- `bunker_public_key` has UNIQUE index (one per system)
- `oauth_applications.client_id` is globally unique

---

## 6. ENCRYPTION & KEY MANAGEMENT

### Key Manager Interface
**Location**: `core/src/encryption/mod.rs`

Two implementations:

#### 1. GCP Key Manager (Production)
- Uses Google Cloud KMS
- Asymmetric encryption
- Project: `openvine-co`
- Managed encryption at service level

#### 2. File Key Manager (Development)
- Local `master.key` file
- Symmetric encryption
- File: `/Users/rabble/code/andotherstuff/keycast/master.key` (45 bytes)

**Selection**:
```rust
if env::var("USE_GCP_KMS").unwrap_or_else(|_| "false".to_string()) == "true" {
    // Use GCP KMS
} else {
    // Use file-based encryption
}
```

### What Gets Encrypted
- User secret keys in `personal_keys.encrypted_secret_key`
- Bundle secret keys in `oauth_authorizations.bunker_secret`

---

## 7. SIGNER DAEMON ARCHITECTURE

### Unified Signer Process
**Location**: `/Users/rabble/code/andotherstuff/keycast/signer/src/main.rs`

- Separate container from API server
- Connects to relays (e.g., relay.damus.io)
- Listens for NIP-46 requests on relay
- Routes requests to correct user/app authorization
- Signs events and returns results

### Two-Service Architecture
1. **API Service** (`keycast-oauth`)
   - Handles user registration, login, OAuth flows
   - Serves web frontend
   - Port: 3000 (local dev), 8080 (Cloud Run)

2. **Signer Service** (`keycast-signer`)
   - Handles NIP-46 signing requests
   - Connects to Nostr relays
   - Port: 8080 (Cloud Run with /health endpoint)

### Communication
- Both share same database: `keycast.db`
- Signal file: `database/.reload_signal` (triggers signer reload)
- Single-instance protection via `database/.signer.pid`

### Signing Activity Log
**Location**: `database/migrations/0009_signing_activity.sql`

```sql
CREATE TABLE signing_activity (
    id INTEGER PRIMARY KEY,
    user_public_key CHAR(64),
    application_id INTEGER,
    bunker_secret TEXT,
    event_kind INTEGER,
    event_content TEXT,
    event_id CHAR(64),
    client_public_key CHAR(64),
    created_at DATETIME
);
```

Enables user to see which apps signed which events and when.

---

## 8. CLOUD DEPLOYMENT

### Services Configuration
**Location**: `service.yaml` (API) and `signer-service.yaml` (Signer)

**Key Features**:
- Knative serving (Google Cloud Run native)
- Litestream for PostgreSQL replication to Cloud Storage
- Gen2 execution environment
- Database in emptyDir (500Mi limit) with Litestream backup
- Two containers per service:
  1. Main app container
  2. Litestream replica container

**Environment Variables**:
- `DATABASE_PATH`: `/data/keycast.db`
- `NODE_ENV`: `production`
- `RUST_LOG`: `info`
- `USE_GCP_KMS`: `true` (production)
- `GCP_PROJECT_ID`: `openvine-co`

---

## 9. BRANDING & CUSTOMIZATION

### Current Customization Points

1. **Email Sender**
   - From: `FROM_EMAIL` env var (currently `noreply@divine.video`)
   - Service: SendGrid via API key

2. **HTML Pages** (in `/public`)
   - `login.html`
   - `register.html`
   - `dashboard.html`
   - `profile.html`
   - Static, served from filesystem

3. **Frontend Framework**
   - HTML/CSS/JavaScript
   - Can be replaced with alternative frontend

4. **NIP-05 Domain**
   - Currently: `login.divine.video`
   - Uses `username@login.divine.video` format
   - Would need per-tenant configuration for multi-domain

### Limitation: Single Branding
- All users see same frontend
- All emails from same sender
- All NIP-05 identifiers use same domain
- No per-tenant customization

---

## 10. SUMMARY: MULTI-DOMAIN REQUIREMENTS

### Architecture Changes Needed

**Database**:
1. Add `tenant_id` to core tables
2. Adjust unique constraints to include tenant_id
3. Migrate data isolation layer

**Authentication**:
1. Extract tenant from request (domain, header, path prefix, or claim)
2. Add tenant context to all queries
3. Validate tenant access for all endpoints

**OAuth**:
1. Per-tenant `oauth_applications` registrations
2. Per-tenant bunker URLs (different relay URLs per tenant possible)
3. Per-tenant NIP-05 discovery endpoints

**Routing**:
1. Extract tenant before routing
2. Mount different subdomains OR use path prefixes
3. Different static files per tenant

**Configuration**:
1. Per-tenant environment variables
2. Per-tenant email settings
3. Per-tenant relay URL selection
4. Per-tenant KMS keys (if desired)

**CORS**:
1. Per-tenant CORS allowed origins
2. Different allowed domains per tenant

### Minimal MVP for Multi-Domain
1. Deploy multiple Keycast instances (simplest)
2. OR add light-weight tenant routing layer
3. OR implement single instance with tenant context middleware

Currently, single-domain deployment is the most straightforward path.

