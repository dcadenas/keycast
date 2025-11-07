# Keycast Deployment Issues

**Date**: 2025-11-04
**Deployment**: keycast-unified @ us-central1
**URLs**:
- https://oauth.divine.video (DNS alias)
- https://keycast-unified-4uaiddnawq-uc.a.run.app (Cloud Run URL)

---

## Current Deployment Status

### Service Configuration
- **Service**: `keycast-unified`
- **Region**: `us-central1`
- **Revision**: `keycast-unified-00027-6sd`
- **Deployed**: 2025-10-30 19:51:01 UTC
- **Container**: `us-central1-docker.pkg.dev/openvine-co/docker/keycast:latest`
- **Binary**: `./keycast` (unified mode - API + Signer combined)
- **Port**: 3000
- **Status**: Ready (service is running)

### Environment Variables
- `NODE_ENV=production`
- `RUST_LOG=info`
- `WEB_BUILD_DIR=/app/web`
- `USE_GCP_KMS=true`
- Database connection (Cloud SQL via secrets)

---

## Issue #1: Route Path Prefix Mismatch

### Problem
Documentation and external references expect routes at `/api/*`, but the unified binary mounts them at root level.

**Expected paths** (from docs/examples):
```
POST /api/auth/register
POST /api/auth/login
GET  /api/user/bunker
```

**Actual paths** (unified binary):
```
POST /auth/register
POST /auth/login
GET  /user/bunker
```

### Root Cause
**Standalone API binary** (`api/src/main.rs` line 165):
```rust
.nest("/api", api::http::routes(...))  // Routes nested under /api
```

**Unified binary** (`signer/src/bin/keycast.rs` line 135):
```rust
.merge(api_routes)  // Routes merged at ROOT level (no nesting)
```

### Impact
- ❌ All documentation examples return 404
- ❌ oauth.divine.video homepage shows incorrect endpoint paths
- ❌ External integrations using `/api/*` paths fail

### Evidence (from logs @ 2025-11-04 15:18-15:19 UTC)
```
POST /api/auth/register → 404 (wrong path)
POST /auth/register → 500 (correct path, but DB error)
GET  / → 200 (works)
GET  /health → 200 (works)
```

### Fix Options

**Option A: Add `/api` prefix to unified binary** (Recommended)
```rust
// In signer/src/bin/keycast.rs line 135
let app = Router::new()
    .route("/health", get(health_check))
    .nest("/api", api_routes)  // Add this nesting
    .layer(cors);
```

**Option B: Update all documentation**
- Change all `/api/*` references to `/*`
- Update homepage HTML
- Update examples and README files
- More work, less consistent with standalone API

**Recommendation**: Option A - Add `/api` prefix nesting to unified binary to match standalone API and documentation.

---

## Issue #2: Database Schema Mismatch (CRITICAL)

### Problem
The `tenants` table has incompatible column types causing all API requests to fail with 500 errors.

### Error Messages (from logs @ 2025-11-04 15:19:09 UTC)
```
ERROR Failed to get/create tenant for domain keycast-unified-4uaiddnawq-uc.a.run.app:
Database error: error returned from database: mismatched types;
Rust type `alloc::string::String` (as SQL type `TEXT`) is not compatible with
SQL type `TIMESTAMPTZ`
```

### Root Cause
Database schema expects `TIMESTAMPTZ` for timestamp columns, but Rust code expects `String`.

**Likely columns affected:**
- `tenants.created_at`
- `tenants.updated_at`
- Other timestamp columns

### Impact
- ❌ Tenant provisioning fails
- ❌ All authenticated endpoints fail (can't create/find tenant)
- ❌ Registration returns 500 error
- ❌ Login returns 500 error
- ❌ Cannot test any API functionality

### Testing Evidence
```bash
curl -X POST https://keycast-unified-4uaiddnawq-uc.a.run.app/auth/register \
  -H 'Content-Type: application/json' \
  --data-raw '{"email":"test@example.com","password":"test123"}'

Response: 500 Internal Server Error
Logs: "Failed to provision tenant"
```

### Fix Required

**Option A: Fix Schema to Match Code**
```sql
-- Check current schema
\d tenants

-- If created_at is TIMESTAMPTZ, change to TEXT or VARCHAR
ALTER TABLE tenants ALTER COLUMN created_at TYPE TEXT;
ALTER TABLE tenants ALTER COLUMN updated_at TYPE TEXT;
```

**Option B: Fix Code to Match Schema**
Update Rust structs to use proper timestamp types:
```rust
// Change from
pub created_at: String,

// To
pub created_at: chrono::DateTime<chrono::Utc>,
```

**Option C: Re-run Migrations Fresh**
```bash
# Drop and recreate database with correct schema
sqlx database drop --database-url $DATABASE_URL
sqlx database create --database-url $DATABASE_URL
sqlx migrate run --database-url $DATABASE_URL --source ./database/migrations
```

**Recommendation**: Option C - Re-run migrations to ensure schema matches code expectations. This is safest and ensures all tables are consistent.

---

## Issue #3: Signer Daemon Database Errors

### Problem
The NIP-46 signer daemon experiences SQL syntax errors when processing requests.

### Error Messages (from logs @ 2025-11-04)
```
ERROR keycast_signer::signer_daemon: Error handling NIP-46 request:
error returned from database: syntax error at end of input
```

### Impact
- ❌ NIP-46 signing requests fail
- ❌ nostrconnect:// flow cannot complete
- ❌ Users cannot use bunker for remote signing

### Root Cause
Likely related to Issue #2 - schema mismatch in related tables:
- `oauth_authorizations` table
- `users` table
- Session/permission tables

### Fix
Same as Issue #2 - re-run migrations to fix schema.

---

## Additional Observations

### DNS Configuration
- `oauth.divine.video` resolves correctly
- Serves the same static HTML as the Cloud Run URL
- But may be cached/proxied through CDN
- Both URLs return identical 404s on `/api/*` paths

### Service Health
- Service reports "Ready" status
- All health checks passing
- No deployment failures
- Container starts successfully
- Issue is purely schema/routing, not infrastructure

---

## Working Endpoints (Confirmed)

These endpoints respond (even though they may error due to DB issues):

```
GET  /                    → 200 (static HTML)
GET  /health              → 200 (health check)
POST /auth/register       → 500 (route exists, DB error)
POST /auth/login          → 500 (route exists, DB error)
```

These endpoints are 404 (wrong prefix):

```
POST /api/auth/register   → 404 (should be /auth/register)
POST /api/auth/login      → 404 (should be /auth/login)
GET  /api/health          → 404 (should be /health)
```

---

## Fix Checklist

### Database Schema Fix
- [ ] Connect to production Cloud SQL instance
- [ ] Backup current database
- [ ] Check `tenants` table schema
- [ ] Re-run SQLx migrations from `./database/migrations/`
- [ ] Verify all tables have correct types
- [ ] Test tenant provisioning

### Route Prefix Fix
- [ ] Add `/api` nesting in `signer/src/bin/keycast.rs`
- [ ] Or update all documentation to use root-level paths
- [ ] Ensure consistency between unified and standalone binaries
- [ ] Update homepage HTML with correct endpoint paths

### Deployment Verification
- [ ] Test registration: `POST /auth/register` or `/api/auth/register`
- [ ] Test login: `POST /auth/login`
- [ ] Test bunker URL retrieval: `GET /user/bunker`
- [ ] Test NIP-46 signer: Send kind 24133 request
- [ ] Verify oauth.divine.video DNS points to working service

### NIP-46 Testing
- [ ] Register test account
- [ ] Get bunker URL
- [ ] Test bunker:// flow with Peek
- [ ] Test nostrconnect:// flow with Peek
- [ ] Verify signing operations work
- [ ] Check relay connectivity (relay.damus.io)

---

## Testing Commands

### Once DB is fixed, test with:

**Register:**
```bash
curl -X POST https://keycast-unified-4uaiddnawq-uc.a.run.app/auth/register \
  -H 'Content-Type: application/json' \
  --data-raw '{"email":"test@example.com","password":"testPassword123"}'
```

**Login:**
```bash
curl -X POST https://keycast-unified-4uaiddnawq-uc.a.run.app/auth/login \
  -H 'Content-Type: application/json' \
  --data-raw '{"email":"test@example.com","password":"testPassword123"}'
```

**Get Bunker URL:**
```bash
curl https://keycast-unified-4uaiddnawq-uc.a.run.app/user/bunker \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

---

## Related Context

**Discovered during**: Peek NIP-46 bunker authentication implementation
**Impact on Peek**: Cannot test nostrconnect:// flow with keycast deployment
**Workaround**: Using nsec.app bunker:// URLs for testing
**Priority**: Low (nsec.app works for MVP, keycast can be fixed later)

---

## Links

- Cloud Run Service: https://console.cloud.google.com/run/detail/us-central1/keycast-unified
- Source Code: /home/daniel/code/nos/keycast
- Deployment Logs: `gcloud run services logs read keycast-unified --region=us-central1`
