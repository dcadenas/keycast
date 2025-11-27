# Keycast Deployment Guide

## Production Services

### Current Active Services

- **`keycast-unified`** (PRODUCTION - login.divine.video)
  - Runs both API + Signer daemon in one container
  - Command: `--args=unified`
  - Domain: https://login.divine.video
  - Memory: 2Gi, CPU: 2
  - Port: 3000

- **`keycast-signer`** (Standalone signer for multi-region)
  - Dedicated signing service
  - Command: `--args=signer`
  - Memory: 1Gi, CPU: 1
  - Port: 8080
  - Not publicly accessible

### Deprecated Services (DO NOT USE)

- **`keycast-oauth`** - Old API-only service, replaced by keycast-unified
- **`keycast-oauth-server`** - Duplicate/abandoned service

## Deployment Process

### Via cloudbuild.yaml (Automated)

```bash
gcloud builds submit --config=cloudbuild.yaml .
```

This builds the Docker image and deploys to:
1. `keycast-unified` (production)
2. `keycast-signer` (standalone signer)

### Manual Deployment

```bash
# Deploy unified service
gcloud run deploy keycast-unified \
  --image=us-central1-docker.pkg.dev/openvine-co/docker/keycast:latest \
  --region=us-central1 \
  --args=unified \
  [... other flags]

# Deploy signer only
gcloud run deploy keycast-signer \
  --image=us-central1-docker.pkg.dev/openvine-co/docker/keycast:latest \
  --region=us-central1 \
  --args=signer \
  [... other flags]
```

## Database Configuration

### CRITICAL: Database Persistence Issue

**Current Problem**: Production uses an ephemeral PostgreSQL database stored at `/app/database/keycast.db` which is RECREATED on every deployment, **losing all data**.

**Litestream Backup Not Working**: There's a path mismatch between:
- Application database: `/app/database/keycast.db`
- Litestream monitoring: `/data/keycast.db`

Litestream is NOT actually backing up the application database!

**Temporary Solution**: The database is mounted in the container's writable layer, but this is not persistent across deployments.

**Proper Solution (In Progress)**: Migrating to Cloud SQL PostgreSQL for persistent storage.

## Service Architecture

```
login.divine.video (DNS)
    ↓
Cloud Load Balancer / Domain Mapping
    ↓
keycast-unified (Cloud Run)
    ├── API Server (port 3000)
    │   ├── /api/auth/*
    │   ├── /api/user/*
    │   ├── /api/oauth/*
    │   └── / (static web files)
    └── Signer Daemon
        └── NIP-46 relay listener
```

## Environment Variables

See `cloudbuild.yaml` for the full list of required environment variables:
- `NODE_ENV=production`
- `USE_GCP_KMS=true`
- `CORS_ALLOWED_ORIGIN=https://login.divine.video`
- `APP_URL=https://login.divine.video`
- etc.

## Secrets (Google Secret Manager)

- `MASTER_KEY_PATH` - Encryption master key
- `SENDGRID_API_KEY` - Email service

## Smoke Tests

cloudbuild.yaml includes automated smoke tests:
- Health endpoint check
- CORS preflight validation

## Troubleshooting

### Deployment went to wrong service
- Check `cloudbuild.yaml` line 27 - should be `keycast-unified`
- Verify `--args=unified` is set (line 36)

### Database reset after deployment
- This is EXPECTED with current architecture (ephemeral database)
- Need to implement persistent database solution

### Service not updating
- Check which revision is serving traffic: `gcloud run services describe keycast-unified --region=us-central1`
- Verify latest image was deployed
