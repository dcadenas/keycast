# OAuth Prompt Parameter & Direct nsec Input

## Overview

Added OAuth 2.0 standard `prompt` parameter support and direct nsec input to the OAuth registration flow.

## 1. OAuth Prompt Parameter

The OAuth authorization endpoint now supports the standard `prompt` parameter for controlling authentication behavior.

### Usage

```
GET /api/oauth/authorize?client_id=...&prompt=login
GET /api/oauth/authorize?client_id=...&prompt=consent
```

### Supported Values

- **`prompt=login`**: Forces fresh login even if user has valid session
  - Clears existing cookie
  - Always shows login form
  - Skips auto-approve flow

- **`prompt=consent`**: Forces explicit consent screen
  - Skips auto-approve even if user previously authorized the app
  - Always shows approval screen for explicit user confirmation

### Implementation Details

- Added `prompt` field to `AuthorizeRequest` struct
- Logic checks `prompt` before auto-approve flow (lines 283-291, 342)
- Compatible with existing OAuth flows (no breaking changes)

## 2. Direct nsec Input in OAuth Registration

Users can now provide their existing Nostr private key directly during OAuth registration, in addition to the existing BYOK flow via code_verifier.

### User Flow

1. User opens OAuth registration form
2. Expands "Advanced: Import existing Nostr key" section (collapsed by default)
3. Enters nsec (nsec1... or 64-char hex)
4. Submits registration
5. Server creates account with user-provided key immediately

### Priority Order

When registering, the backend uses this priority:

1. **Direct nsec input** (`req.nsec`) - from advanced section
2. **BYOK pubkey** (`req.pubkey`) - from demo client, nsec comes via code_verifier
3. **Auto-generate** - server creates new key

### Frontend Changes

- Added nostr-tools library to OAuth page for key handling
- Collapsed advanced section with toggle animation
- Password field for nsec input (supports both formats)
- Simple UX for new users (advanced section hidden by default)

### Backend Changes

- Added `nsec` field to `OAuthRegisterRequest` struct
- Updated `oauth_register` handler to parse nsec and create keys immediately
- Server validates nsec format and creates `personal_keys` during registration

### Security Notes

- nsec sent over HTTPS POST (same security as password)
- Server validates nsec format before storing
- Keys encrypted at rest with AES-256-GCM

## 3. Security Settings Refactor

### Password-Gated Flow

- Single password input at top of page
- Must verify password before accessing any security features
- Both Export and Change sections locked until password verified
- Lock/unlock without page reload

### Removed Auto-Generate from Change Key

- "Change Private Key" section now requires importing existing key
- No auto-generate option (prevents accidental identity loss)
- User must explicitly provide nsec to change keys

## Migration Notes

All changes are backward compatible. Existing OAuth clients work without modification. The `prompt` parameter is optional and existing flows continue to work as before.

## Files Changed

- `api/src/api/http/oauth.rs` - OAuth prompt logic and nsec input handling
- `web/src/routes/settings/security/+page.svelte` - Security settings refactor
