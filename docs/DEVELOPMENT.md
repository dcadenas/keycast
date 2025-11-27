# Keycast Development Guide

## Quick Start

### Local Development & Testing

**Test locally before deploying** (30 seconds vs 40 minutes):

```bash
# Clean start
docker-compose -f docker-compose.dev.yml down -v
rm -f database/keycast.db*

# Run integration tests
./test-local.sh

# Services will be available at:
# - API:  http://localhost:3000
# - Web:  http://localhost:5173
```

### Deploy to Production

**Only deploy after local tests pass:**

```bash
gcloud builds submit --config=cloudbuild.yaml --project=openvine-co
```

## Testing Strategy

### Local Integration Tests (30s)
```bash
./test-local.sh
```
- Builds and starts full stack with Docker Compose
- Tests health endpoints, CORS, API connectivity
- Runs in ~30 seconds vs 8+ minutes for Cloud Build
- **Always run before deploying**

### API Integration Tests
```bash
# Local
./tests/integration/test-api.sh

# Production
API_URL=https://login.divine.video FRONTEND_URL=https://login.divine.video \
  ./tests/integration/test-api.sh
```
Tests:
- Health & infrastructure (health endpoint, CORS)
- Teams API authentication
- API structure & error handling
- Security headers & CORS restrictions

### E2E Frontend Tests
```bash
# Local
./tests/e2e/test-frontend.sh

# Production (when frontend is deployed)
BASE_URL=https://login.divine.video API_URL=https://login.divine.video \
  ./tests/e2e/test-frontend.sh
```
Tests:
- Page loading & rendering
- Frontend-API integration
- Static assets
- Security headers
- Performance (load time, page size)

### Unit Tests (TODO)
```bash
cargo test --workspace
```

## Architecture

### API (Port 3000)
- Rust/Axum
- PostgreSQL database
- NIP-46 bunker implementation

### Web (Port 5173)
- SvelteKit
- Bun runtime
- Connects to API

### Configuration

#### Build-time (baked into image)
- `VITE_DOMAIN` - API URL for frontend

#### Runtime (environment variables)
- `CORS_ALLOWED_ORIGIN` - Frontend origin for CORS
- `APP_URL` - Application base URL
- `USE_GCP_KMS` - Use GCP Key Management (production)
- `SENDGRID_API_KEY` - Email service

## Known Issues

See the comprehensive analysis for 26 production-readiness issues.

### Critical (Being Fixed)
- ✅ CORS configuration (now reads from env)
- ✅ Build args for VITE_DOMAIN
- ✅ Deployment smoke tests
- ⏳ Cloud Build compilation errors

### High Priority
- No integration/e2e tests (test infrastructure created)
- No structured logging
- No error monitoring
- Master key baked into image
- No rate limiting

## Deployment Checklist

Before deploying:
- [ ] Run `./test-local.sh` successfully
- [ ] Check git status is clean
- [ ] Review changed files
- [ ] Update CHANGELOG (if exists)

After deploying:
- [ ] Check Cloud Build logs
- [ ] Verify smoke tests pass
- [ ] Test registration flow manually
- [ ] Check logs for errors
