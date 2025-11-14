
> ✅ **COMPLETED** - This plan was implemented in commits 389822b and 6b46457
> 
> See:
> - core/src/authorization_channel.rs (implementation)
> - Commit 389822b: Add MPSC authorization channel infrastructure  
> - Commit 6b46457: Implement MPSC channel for instant authorization loading
> 
> Status: File-based reload signal completely replaced with MPSC channel


# MPSC Channel Refactor Plan - Authorization Reload

**Date:** 2025-11-08
**Status:** Planned (not implemented)
**Priority:** Medium (performance optimization)

---

## Current Architecture (File-Based)

### How It Works Now

```
API creates authorization
    ↓
Write to database
    ↓
Create file: database/.reload_signal
    ↓
Signer polls file every 1 second
    ↓
Detects file → Reload ALL authorizations from DB
    ↓
Delete signal file
```

### Problems

1. **Latency:** Up to 1 second delay before signer knows about new authorization
2. **File I/O overhead:** Creating/deleting files for IPC
3. **Full reload:** Always reloads ALL authorizations from DB (wasteful)
4. **Legacy pattern:** Leftover from when they were separate processes
5. **No granular control:** Can't add/remove specific authorization

---

## Proposed Architecture (MPSC Channel)

### Design Principles

**Rust Best Practices:**
- Use `tokio::sync::mpsc` for async message passing
- Bounded channel to prevent memory leaks
- Enum for message types (explicit, type-safe)
- Database remains source of truth (reload on startup)
- Graceful shutdown handling

### Message Types

```rust
#[derive(Debug, Clone)]
pub enum AuthorizationCommand {
    /// Add or update a single authorization
    Upsert {
        id: i32,
        user_pubkey: String,
        bunker_pubkey: String,
        bunker_secret: Vec<u8>,
        connection_secret: String,
        relays: Vec<String>,
        policy_id: Option<i32>,
    },

    /// Remove an authorization (revoked)
    Remove {
        bunker_pubkey: String,
    },

    /// Full reload from database (e.g., after migration)
    ReloadAll,
}
```

### Architecture

```
┌─────────────┐                    ┌──────────────────┐
│   API Task  │                    │  Signer Daemon   │
│             │                    │                  │
│  POST login │──── INSERT ────▶   │   PostgreSQL     │
│             │       auth         │                  │
│             │                    └──────────────────┘
│             │                              ▲
│      │      │                              │ startup
│      │      │     MPSC Channel             │ load all
│      └──────┼────────────────────────────┐ │
│             │  AuthorizationCommand      │ │
│             │  ::Upsert { ... }          ▼ ▼
│             │                    ┌──────────────────┐
│             │                    │   Signer Task    │
│             │                    │                  │
│             │                    │  HashMap<        │
│             │                    │    bunker_pubkey,│
│             │                    │    handler       │
│             │                    │  >               │
│             │                    │                  │
│             │                    │  + Instant add   │
│             │                    │  + Instant remove│
│             │                    └──────────────────┘
└─────────────┘

API sends → Signer receives → Updates HashMap → Ready for NIP-46
```

---

## Implementation Plan

### Phase 1: Define Channel Infrastructure

**File:** `core/src/authorization_channel.rs` (new)

```rust
use tokio::sync::mpsc;

pub type AuthorizationSender = mpsc::Sender<AuthorizationCommand>;
pub type AuthorizationReceiver = mpsc::Receiver<AuthorizationCommand>;

pub const CHANNEL_BUFFER_SIZE: usize = 100;

#[derive(Debug, Clone)]
pub enum AuthorizationCommand {
    Upsert {
        id: i32,
        user_pubkey: String,
        bunker_pubkey: String,
        bunker_secret: Vec<u8>,
        connection_secret: String,
        relays: Vec<String>,
        policy_id: Option<i32>,
    },
    Remove {
        bunker_pubkey: String,
    },
    ReloadAll,
}

pub fn create_channel() -> (AuthorizationSender, AuthorizationReceiver) {
    mpsc::channel(CHANNEL_BUFFER_SIZE)
}
```

### Phase 2: Update Signer Daemon

**File:** `signer/src/signer_daemon.rs`

**Changes:**

1. **Add channel receiver to UnifiedSigner:**
```rust
pub struct UnifiedSigner {
    // ... existing fields
    auth_rx: AuthorizationReceiver,  // NEW
}
```

2. **Replace file polling with channel receive:**
```rust
// REMOVE: File polling loop
// let mut interval = tokio::time::interval(Duration::from_secs(1));

// ADD: Channel receive loop
loop {
    tokio::select! {
        // Handle NIP-46 requests
        Ok(event) = client.recv() => {
            // existing NIP-46 logic
        }

        // Handle authorization updates (INSTANT)
        Some(cmd) = self.auth_rx.recv() => {
            match cmd {
                AuthorizationCommand::Upsert { .. } => {
                    // Add single authorization to HashMap
                    self.add_authorization_handler(cmd).await;
                }
                AuthorizationCommand::Remove { bunker_pubkey } => {
                    // Remove from HashMap
                    self.handlers.write().await.remove(&bunker_pubkey);
                }
                AuthorizationCommand::ReloadAll => {
                    // Full reload from DB (rare)
                    self.reload_all_authorizations().await;
                }
            }
        }
    }
}
```

3. **Add helper method:**
```rust
async fn add_authorization_handler(&self, cmd: AuthorizationCommand) {
    if let AuthorizationCommand::Upsert {
        bunker_pubkey,
        bunker_secret,
        connection_secret,
        policy_id,
        ..
    } = cmd {
        // Decrypt secret key
        let secret_key = self.key_manager.decrypt(&bunker_secret).await.unwrap();

        // Create handler
        let handler = AuthorizationHandler::new(
            Keys::parse(&hex::encode(secret_key)).unwrap(),
            connection_secret,
            policy_id,
            // ... other fields
        );

        // Insert into HashMap
        self.handlers.write().await.insert(bunker_pubkey, Arc::new(handler));

        tracing::info!("Added authorization handler for bunker: {}", bunker_pubkey);
    }
}
```

### Phase 3: Update API Routes

**File:** `api/src/api/http/routes.rs`

**Add sender to AuthState:**
```rust
pub struct AuthState {
    pub state: ApiState,
    pub auth_tx: AuthorizationSender,  // NEW
}
```

### Phase 4: Update Login Endpoint

**File:** `api/src/api/http/auth.rs`

**Replace file signal with channel send:**
```rust
// REMOVE:
let signal_file = std::path::Path::new("database/.reload_signal");
std::fs::File::create(signal_file)?;

// REPLACE WITH:
let _ = auth_state.auth_tx.send(AuthorizationCommand::Upsert {
    id: auth_id,
    user_pubkey: public_key.clone(),
    bunker_pubkey: public_key.clone(),
    bunker_secret: encrypted_secret.clone(),
    connection_secret: connection_secret.clone(),
    relays: vec![
        "wss://relay.damus.io".to_string(),
        "wss://nos.lol".to_string(),
        "wss://relay.nsec.app".to_string()
    ],
    policy_id: Some(policy_id),
}).await;
```

**Error handling:**
```rust
if let Err(e) = auth_state.auth_tx.send(cmd).await {
    tracing::error!("Failed to notify signer of new authorization: {}", e);
    // Authorization is in DB, signer will load on restart
    // Non-fatal error, return success to user
}
```

### Phase 5: Update OAuth Token Endpoint

**File:** `api/src/api/http/oauth.rs`

Same pattern as login - replace file signal with channel send.

### Phase 6: Update Revoke Endpoint

**File:** `api/src/api/http/auth.rs` - `revoke_session()`

```rust
// After setting revoked_at in DB:
let _ = auth_state.auth_tx.send(AuthorizationCommand::Remove {
    bunker_pubkey: bunker_pubkey.clone(),
}).await;
```

### Phase 7: Wire It All Together

**File:** `keycast/src/main.rs`

```rust
use keycast_core::authorization_channel;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create channel
    let (auth_tx, auth_rx) = authorization_channel::create_channel();

    // Create signer with receiver
    let signer = UnifiedSigner::new(
        database.pool.clone(),
        database.key_manager.clone(),
        auth_rx,  // Pass receiver
    ).await?;

    // Create API state with sender
    let auth_state = AuthState {
        state: api_state,
        auth_tx: auth_tx.clone(),  // Clone sender for API
    };

    // Spawn both tasks
    let signer_handle = tokio::spawn(async move {
        signer.run().await
    });

    let api_handle = tokio::spawn(async move {
        axum::serve(listener, app).await
    });

    // Wait for either to finish
    tokio::select! {
        _ = signer_handle => {},
        _ = api_handle => {},
    }

    Ok(())
}
```

---

## Design Considerations

### 1. Channel Size (Bounded vs Unbounded)

**Choice:** Bounded channel with size 100

**Rationale:**
- Prevents memory leaks if signer crashes
- 100 is plenty (typical rate: 1-10 authorizations per minute)
- If full, send fails gracefully (DB persists data, reload on restart)

### 2. Error Handling

**If channel send fails:**
- Log error
- Continue execution (non-fatal)
- Authorization is persisted in DB
- Signer will pick it up on next restart or ReloadAll command

**If channel is full:**
- Oldest message dropped (bounded behavior)
- Log warning
- Could trigger ReloadAll as fallback

### 3. Startup Sequence

**Critical:** Database load must complete before processing channel messages

**Why:** Channel might receive Remove before signer loaded that authorization

**Solution:**
```rust
// Load all from DB first
signer.load_all_authorizations().await;

// Then start processing channel
loop {
    match auth_rx.recv().await {
        // ... handle commands
    }
}
```

### 4. Graceful Shutdown

```rust
impl Drop for UnifiedSigner {
    fn drop(&mut self) {
        // Close channel receiver
        self.auth_rx.close();
        tracing::info!("Signer daemon shutting down gracefully");
    }
}
```

### 5. Testing Strategy

**Unit tests:**
- Channel send/receive
- Command enum serialization
- Handler add/remove logic

**Integration tests:**
- Login → authorization → signer receives → NIP-46 works
- Revoke → signer receives → handler removed
- Channel full → graceful degradation

---

## Migration Path

### Step 1: Add channel infrastructure (non-breaking)
- Add `authorization_channel` module
- Don't use it yet, just compile

### Step 2: Update UnifiedSigner (internal change)
- Add receiver parameter
- Keep file polling as fallback
- Log both mechanisms

### Step 3: Update API to send to channel (parallel)
- Send to channel AND create file
- Monitor both work

### Step 4: Remove file polling (breaking)
- Delete file watching code
- Channel is only mechanism

### Step 5: Cleanup
- Remove signal file creation from API
- Remove file system polling code
- Update documentation

---

## Performance Impact

### Before (File-Based)
- **Latency:** 0-1000ms (average 500ms)
- **CPU:** File system poll every second
- **I/O:** File create/delete per authorization
- **Reload cost:** Query all authorizations from DB

### After (MPSC Channel)
- **Latency:** <1ms (instant)
- **CPU:** Event-driven (no polling)
- **I/O:** None
- **Reload cost:** Only load on startup or explicit ReloadAll

### Estimated Improvement
- **99% latency reduction** (500ms → <1ms)
- **Eliminates polling overhead** (1 check/second → 0)
- **Granular updates** (add one vs reload all)

---

## Rust Guidelines Compliance

### Microsoft Pragmatic Rust Guidelines

**Error Handling:**
- ✅ Channel send errors are logged but non-fatal
- ✅ Database remains source of truth (recoverable state)
- ✅ Explicit error types (not generic)

**Async Patterns:**
- ✅ Use `tokio::select!` for concurrent operations
- ✅ Bounded channels prevent unbounded growth
- ✅ Graceful shutdown via Drop trait

*   ✅ No blocking operations in async context

**API Design:**
- ✅ Clear ownership (sender cloned to API, receiver moved to signer)
- ✅ Type-safe messages (enum not stringly-typed)
- ✅ Internal implementation detail (not exposed in public API)

**Safety:**
- ✅ No unsafe blocks needed
- ✅ Channel provides Sync/Send guarantees
- ✅ Arc<RwLock> for shared HashMap (existing pattern maintained)

---

## Alternative Designs Considered

### Alternative 1: Shared Arc<RwLock<HashMap>>

**Approach:** API and Signer share the same HashMap

```rust
let handlers = Arc::new(RwLock::new(HashMap::new()));
let api_handlers = handlers.clone();
let signer_handlers = handlers.clone();

// API directly inserts
api_handlers.write().await.insert(key, handler);

// Signer directly reads
let handler = signer_handlers.read().await.get(&key);
```

**Pros:**
- Instant (no channel overhead)
- Simple

**Cons:**
- ❌ Tight coupling (API knows signer internals)
- ❌ Lock contention (API writes, signer reads frequently)
- ❌ API must construct full handler (needs decryption, policy loading)
- ❌ Violates separation of concerns

**Verdict:** REJECTED - Message passing is cleaner

### Alternative 2: Database Polling

**Approach:** Signer polls DB for changes every second

**Cons:**
- ❌ Still has latency
- ❌ DB query overhead
- ❌ Complex change detection logic

**Verdict:** REJECTED - Worse than current file approach

### Alternative 3: Broadcast Channel

**Approach:** Multiple consumers could listen for authorization updates

**When useful:** If we add multiple signer instances for load balancing

**Current:** Not needed (single signer)

**Future:** Could upgrade mpsc → broadcast if needed

---

## Implementation Checklist

### Core Infrastructure
- [ ] Create `core/src/authorization_channel.rs` module
- [ ] Define `AuthorizationCommand` enum
- [ ] Add channel creation helper
- [ ] Add to `core/src/lib.rs` exports

### Signer Daemon
- [ ] Add `auth_rx` field to `UnifiedSigner`
- [ ] Add `add_authorization_handler()` method
- [ ] Add `remove_authorization_handler()` method
- [ ] Replace file polling with `tokio::select!` on channel
- [ ] Add error logging for channel errors
- [ ] Test graceful shutdown

### API Routes
- [ ] Add `auth_tx` to `AuthState` struct
- [ ] Update `routes::create_router()` to accept sender
- [ ] Clone sender for each route that creates/revokes authorizations

### Login Endpoint
- [ ] Replace file signal with `auth_tx.send(Upsert)`
- [ ] Handle send errors gracefully
- [ ] Remove file system code

### Register Endpoint
- [ ] Replace file signal with `auth_tx.send(Upsert)`
- [ ] Handle send errors gracefully
- [ ] Remove file system code

### OAuth Token Endpoint
- [ ] Replace file signal with `auth_tx.send(Upsert)`
- [ ] Handle send errors gracefully

### Revoke Endpoint
- [ ] Add `auth_tx.send(Remove)` after DB update
- [ ] Handle send errors gracefully

### Main Binary
- [ ] Create channel in `main()`
- [ ] Pass receiver to signer constructor
- [ ] Pass sender to API state
- [ ] Verify both tasks can communicate

### Testing
- [ ] Unit test: Channel message passing
- [ ] Integration test: Login → signer receives → handler added
- [ ] Integration test: Revoke → signer receives → handler removed
- [ ] Stress test: 100 rapid authorizations
- [ ] Test: Channel full scenario

### Cleanup
- [ ] Remove all `database/.reload_signal` file creation code
- [ ] Remove file polling from signer daemon
- [ ] Update documentation
- [ ] Update CLAUDE.md if architecture described there

---

## Rollback Plan

**If issues arise:**
1. Revert to file-based approach (one commit)
2. Channel infrastructure can stay (unused, no harm)
3. Database schema unchanged (no migrations)

**Git strategy:**
- One commit: "Add MPSC authorization channel infrastructure"
- One commit: "Switch signer to use MPSC channel"
- One commit: "Switch API to use MPSC channel"
- One commit: "Remove file-based reload signal"

Each commit is independently revertible.

---

## Performance Monitoring

**Metrics to track:**
- Authorization creation → NIP-46 ready latency
- Channel queue depth (should stay near 0)
- Failed channel sends (should be 0)

**Logging to add:**
```rust
tracing::debug!(
    "Authorization added via channel in {}ms",
    latency
);
```

---

## Future Enhancements

### 1. Authorization Updates
Currently only add/remove. Could add Update for:
- Policy changes
- Relay list updates
- Expiration time changes

### 2. Batch Operations
For bulk imports:
```rust
AuthorizationCommand::UpsertBatch {
    authorizations: Vec<AuthorizationData>
}
```

### 3. Health Check
Expose channel queue depth in `/health` endpoint:
```json
{
  "signer": {
    "loaded_authorizations": 42,
    "pending_commands": 0
  }
}
```

---

## Estimated Effort

- **Implementation:** 2-3 hours
- **Testing:** 1-2 hours
- **Documentation:** 30 minutes
- **Total:** Half day of focused work

---

## Notes

**Why not just restart signer on new authorization?**
- Restarting loses in-flight NIP-46 requests
- Relay connections would drop
- Wasteful (reload all authorizations)

**Why not use notify/watch crate for file watching?**
- Still file-based (same fundamental issues)
- Channel is idiomatic Rust async pattern
- Better performance characteristics

**When to use file vs channel:**
- **File:** Cross-process communication (different binaries)
- **Channel:** In-process communication (different tasks in same binary)

Since we have a unified binary, channels are the right choice.

---

## Conclusion

This refactor improves:
1. **Latency:** 500ms average → <1ms
2. **CPU usage:** Constant polling → event-driven
3. **Code clarity:** Intent is explicit (message passing)
4. **Rust idioms:** Channels for task communication

The current file-based approach WORKS but is a legacy pattern. MPSC refactor is a quality-of-life improvement, not a critical bug fix.

**Recommendation:** Implement in next focused session after current PKCE/OAuth work is complete.

---

## Follow-Up Work: OAuth Policy Enforcement

**Status:** Not implemented (TODO in signer_daemon.rs:711)

After MPSC refactor is complete, implement policy enforcement for OAuth authorizations:

### Current Gap
OAuth authorizations have `policy_id` in database but `OAuthAuthorization::validate_policy()` always returns `Ok(true)` - no actual permission checking.

**File:** `core/src/types/oauth_authorization.rs` (lines 73-125)

### What Needs Implementation

1. **Load policy permissions** when creating OAuth authorization handlers in signer
2. **Check permissions before signing** in `handle_sign_event()`
3. **Enforce restrictions:**
   - `allowed_kinds`: Block unauthorized event kinds
   - `content_filter`: Filter events by content regex
   - `encrypt_to_self`: Restrict encryption/decryption operations

4. **HTTP signing endpoint:** Already validates policies (auth.rs:1328-1395)
   - Use same logic in signer daemon for NIP-46 requests

### Implementation Notes

- Regular team authorizations ALREADY enforce policies correctly
- OAuth authorizations need same `CustomPermission` validation
- Load policy permissions from database when handler is created
- Store in handler for fast validation during signing

**Location of TODO:** `signer/src/signer_daemon.rs:711`

**Estimated effort:** 2-3 hours after MPSC refactor
