# Keycast - Pending Work

**Last Updated:** 2025-11-13
**Branch:** feat/oauth-pkce

> ⚠️ **NOTE:** This file is being deprecated in favor of docs/ISSUES.md
>
> Major work items have been completed. For current active work, see:
> - **docs/ISSUES.md** - 14 active issues (production readiness)
> - **docs/archive/COMPLETED_ISSUES.md** - 16 resolved issues

---

## Previously Tracked Items - Now Complete ✅

### 1. Auth Method Tracking
**Status:** ✅ COMPLETE
- All `setCurrentUser` calls pass auth method parameter
- Team pages conditionally sign based on authMethod
- No NIP-07 popups for cookie users

### 2. MPSC Channel Refactor
**Status:** ✅ COMPLETE (Commits 389822b, 6b46457)
- File-based reload signal removed
- tokio::sync::mpsc channel with instant updates
- Implemented in core/src/authorization_channel.rs

### 3. UI Improvements
**Status:** ✅ MOSTLY COMPLETE
- Header visibility working correctly
- Route organization clean
- Minor polish items tracked in Issue #24

---

## Current Active Work

All active work is now tracked in **docs/ISSUES.md**:

**Immediate Priority:**
- Issue #11: Add rate limiting (HIGH - 3-4 hours)
- Issue #12: Health check validation (HIGH - 1-2 hours)
- Issue #28: Fix 3 disabled tests (HIGH - 8-12 hours)

**See docs/ISSUES.md for complete list and prioritization.**
