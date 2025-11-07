# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Keycast is a secure remote signing and permissions system for teams using Nostr. It provides NIP-46 remote signing, team-based key management, and flexible permissions policies. The project consists of three main Rust workspaces:

- **api**: Axum-based HTTP API for team management, authentication, and OAuth 2.0 authorization
- **core**: Shared business logic, database models, encryption, and custom permissions system
- **signer**: Unified NIP-46 signer daemon that handles multiple bunker connections in a single process
- **web**: SvelteKit frontend application (uses Bun for package management)

## Development Commands

### Setup

```bash
# Install workspace dependencies
bun install

# Install web dependencies
cd web && bun install

# Generate master encryption key (stores in ./master.key)
bun run key:generate

# Reset database (drop, create, run migrations)
bun run db:reset
```

### Running Dev Server

```bash
# Run all services (API + Web + Signer) with hot reload
bun run dev

# Run individual services
bun run dev:api     # Rust API on http://localhost:3000
bun run dev:web     # SvelteKit on https://localhost:5173
bun run dev:signer  # NIP-46 signer daemon
```

### Building

```bash
# Build all components
bun run build

# Build individual components
bun run build:api
bun run build:web
bun run build:signer
```

### Testing

```bash
# Run Rust tests (OAuth integration tests)
cd api && cargo test

# Run individual test files
cd api && cargo test --test oauth_integration_test
cd api && cargo test --test oauth_unit_test
```

## Architecture

### Multi-Authentication System

The web admin supports three authentication methods, all converging to unified NIP-98 request signing:

1. **NIP-07 Browser Extension**: For whitelisted team admins with browser extension (nos2x, Alby, etc.)
2. **Email/Password**: For personal users, returns bunker URL stored in localStorage
3. **NIP-46 Bunker URL**: For power users with existing bunker URLs (dogfooding)

**Unified Flow**: All methods → Bunker URL credential → BunkerSigner → NIP-98 signed requests

**Authentication Architecture**:
- Email login creates `oauth_authorization` for app="keycast-web-admin"
- Returns bunker URL: `bunker://<user_pubkey>?relay=<relay>&secret=<secret>`
- Frontend uses nostr-tools BunkerSigner to sign NIP-98 auth headers
- All authenticated API requests include NIP-98 signature in Authorization header
- Backend extracts pubkey from NIP-98 event, validates signature

**Permission Model**:
- **Whitelist** (VITE_ALLOWED_PUBKEYS): Can create teams, full admin access
- **Team Membership**: Can view teams they belong to, role-based permissions (admin/member)
- **Personal Keys**: Can manage their own OAuth authorizations

**Key Types**:
- Regular `Authorization`: Team-managed keys with separate bunker keypair and user signing key
- `OAuthAuthorization`: Personal user keys where the user's own keypair acts as both bunker and signer

### Database & Encryption

- SQLite database with SQLx for compile-time query verification
- AES-256-GCM row-level encryption for all private keys (encrypted at rest, decrypted only when used)
- Supports file-based key manager (default) or GCP KMS (`USE_GCP_KMS=true`)
- Database migrations in `database/migrations/`

Key tables:
- `users`: Nostr public keys
- `teams`: Team containers
- `team_users`: Team membership with roles (admin/member)
- `stored_keys`: Encrypted Nostr keypairs managed by teams
- `policies`: Named permission sets
- `permissions`: Custom permission configurations (JSON)
- `policy_permissions`: Links policies to permissions
- `authorizations`: NIP-46 remote signing credentials for team keys
- `oauth_authorizations`: OAuth-based personal auth with NIP-46 support

### Custom Permissions System

Custom permissions implement the `CustomPermission` trait (`core/src/traits.rs`) with three methods:
- `can_sign(&self, event: &UnsignedEvent) -> bool`
- `can_encrypt(&self, plaintext: &str, pubkey: &str) -> bool`
- `can_decrypt(&self, ciphertext: &str, pubkey: &str) -> bool`

When adding a new custom permission:
1. Create implementation in `core/src/custom_permissions/`
2. Add to `AVAILABLE_PERMISSIONS` in `core/src/custom_permissions/mod.rs`
3. Add to `AVAILABLE_PERMISSIONS` in `web/src/lib/types.ts`
4. Add case to `to_custom_permission()` in `core/src/types/permission.rs`

Existing permissions:
- `allowed_kinds`: Restrict signing/encryption by Nostr event kind
- `content_filter`: Filter events by content regex patterns
- `encrypt_to_self`: Restrict encryption/decryption to user's own pubkey

### Signer Daemon Architecture

The `keycast_signer` binary (`signer/src/main.rs`) is a unified NIP-46 signer daemon:
- Single process handles all active authorizations (both team and OAuth)
- Loads all authorizations on startup into in-memory HashMap (bunker_pubkey -> handler)
- Connects to all configured relays for all authorizations
- Routes incoming NIP-46 requests to appropriate authorization based on recipient pubkey
- Validates requests against policy permissions before signing/encrypting/decrypting
- Supports both regular team authorizations and OAuth personal authorizations

### API Routes Structure

Key endpoints (see `api/src/api/http/routes.rs`):

**Authentication (First-Party)**:
- `/api/auth/register`: Register with email/password, optional nsec import, returns bunker URL
- `/api/auth/login`: Login with email/password, returns bunker URL for NIP-98 signing
- CORS: Restrictive (ALLOWED_ORIGINS env var)

**OAuth (Third-Party)**:
- `/api/oauth/authorize`: OAuth authorization flow (GET shows approval page, POST processes approval)
- `/api/oauth/token`: Exchange authorization code for bunker URL
- CORS: Permissive (any origin)

**User Management (NIP-98 Auth Required)**:
- `/api/user/oauth-authorizations`: List personal OAuth authorizations
- `/api/user/oauth-authorizations/:id`: Revoke authorization
- `/api/user/bunker`: Get personal NIP-46 bunker URL (legacy)

**Team Management (NIP-98 Auth Required)**:
- `/api/teams/*`: Team CRUD, member management, key management, policies
- Requires whitelist or team membership

### Environment Variables

Development (`.env` in `/web`):
- `VITE_ALLOWED_PUBKEYS`: Comma-separated pubkeys for dev access

Production (set via docker-compose or system):
- `MASTER_KEY_PATH`: Path to master encryption key file (default: `./master.key`)
- `USE_GCP_KMS`: Use Google Cloud KMS instead of file-based encryption (default: `false`)
- `RUST_LOG`: Log level configuration (e.g., `debug`, `warn,keycast_signer=debug`)
- `ALLOWED_ORIGINS`: Comma-separated list of allowed CORS origins for auth endpoints (e.g., `https://app.keycast.com,http://localhost:5173`)

## Nostr Protocol Integration

- Uses `nostr-sdk` crate (from git, specific revision) with NIP-04, NIP-44, NIP-46, NIP-49, NIP-59 support
- NIP-46 remote signing: Clients connect via bunker URLs (`bunker://<pubkey>?relay=<relay>&secret=<secret>`)
- NIP-98 HTTP Auth: Web app signs HTTP requests with Nostr events for API authentication

## Deployment

Production deployment uses Docker:
```bash
# Initialize with domain
bash scripts/init.sh <domain>

# Build and run
sudo docker compose up -d --build

# Update
git pull && sudo docker compose up -d --build
```

Reverse proxy: Included `docker-compose.yml` has Caddy labels for automatic SSL cert generation.

## Notes

- All sensitive keys are encrypted at rest with AES-256-GCM
- Master encryption key must be generated before first run (`bun run key:generate`)
- Database uses SQLite with automatic migrations on startup
- Signer daemon monitors database for new/removed authorizations and adjusts connections accordingly
- Build issues on low-memory VMs: Need 2GB+ RAM for Vite build; may require swap space or retries
