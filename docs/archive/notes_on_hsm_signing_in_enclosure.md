⏺ HSM-Based Signing Architecture for Keycast

  Current Implementation (Encryption-based)

  Database Schema:
  personal_keys (
    user_public_key TEXT,
    encrypted_secret_key BLOB,  -- Encrypted 32-byte secret key
    bunker_secret TEXT
  )

  Flow:
  1. Registration: Generate Nostr keypair → Encrypt secret key with KMS → Store encrypted blob
  2. Bunker startup: Load encrypted blobs → Call KMS decrypt → Hold plaintext keys in memory
  3. Signing: Use plaintext key in application memory to sign events
  4. Security issue: Keys exist in application memory, vulnerable to memory dumps/exploits

  HSM-Based Implementation (Asymmetric Signing)

  Database Schema Changes

  personal_keys (
    user_public_key TEXT,         -- Still needed for bunker URL
    kms_key_name TEXT,             -- e.g., "projects/X/locations/Y/keyRings/Z/cryptoKeys/user-abc123"
    kms_key_version TEXT,          -- e.g., "1"
    bunker_secret TEXT
  )

  Registration Flow

  // api/src/api/http/auth.rs - register()

  // Instead of generating keypair locally:
  // let keys = Keys::generate();

  // Create HSM key in Cloud KMS:
  let key_name = format!("user-{}", uuid::Uuid::new_v4());
  let kms_key = kms_client.create_crypto_key(
      parent: "projects/PROJECT/locations/LOCATION/keyRings/nostr-keys",
      crypto_key_id: key_name,
      crypto_key: CryptoKey {
          purpose: AsymmetricSign,
          version_template: {
              algorithm: EC_SIGN_SECP256K1_SHA256,
              protection_level: HSM,  // <-- Key never leaves HSM hardware
          }
      }
  ).await?;

  // Get the public key from HSM
  let public_key_pem = kms_client
      .get_public_key(kms_key.name + "/cryptoKeyVersions/1")
      .await?
      .pem;

  // Parse PEM to extract secp256k1 public key
  let nostr_pubkey = parse_secp256k1_public_key_from_pem(&public_key_pem)?;

  // Store KMS key reference (not encrypted key!)
  sqlx::query(
      "INSERT INTO personal_keys (user_public_key, kms_key_name, kms_key_version, bunker_secret)
       VALUES (?1, ?2, ?3, ?4)"
  )
  .bind(nostr_pubkey.to_hex())
  .bind(kms_key.name)
  .bind("1")
  .bind(bunker_secret)
  .execute(pool)
  .await?;

  Bunker Startup Flow

  // signer/src/personal_bunker.rs

  // Load personal keys from database
  let personal_keys: Vec<(String, String, String, String)> = sqlx::query_as(
      "SELECT user_public_key, kms_key_name, kms_key_version, bunker_secret 
       FROM personal_keys"
  )
  .fetch_all(&pool)
  .await?;

  // No decryption needed! Just pass KMS key references
  for (pubkey, kms_key_name, kms_key_version, bunker_secret) in personal_keys {
      let task = tokio::spawn(async move {
          serve_bunker_with_hsm(
              pubkey,
              kms_key_name,
              kms_key_version,
              bunker_secret,
              relay_url,
              kms_client
          ).await
      });
  }

  Signing Flow

  // New trait for signing (replaces KeyManager decrypt)
  #[async_trait]
  trait Signer {
      async fn sign(&self, digest: &[u8]) -> Result<Signature>;
  }

  struct HsmSigner {
      kms_client: KeyManagementServiceClient,
      key_name: String,
      key_version: String,
  }

  impl Signer for HsmSigner {
      async fn sign(&self, digest: &[u8]) -> Result<Signature> {
          // Send digest to HSM for signing
          let response = self.kms_client.asymmetric_sign(
              name: format!("{}/cryptoKeyVersions/{}", self.key_name, self.key_version),
              digest: Digest {
                  sha256: digest.to_vec(),  // Nostr uses SHA256 of event
              }
          ).await?;

          // HSM returns DER-encoded signature
          // Parse to get r and s components
          let (r, s) = parse_der_signature(&response.signature)?;

          // Return as Nostr signature
          Ok(Signature::from_compact(&[r, s].concat())?)
      }
  }

  // In NIP-46 request handler:
  async fn handle_sign_event_request(
      event: UnsignedEvent,
      signer: &HsmSigner,  // Not Keys anymore!
  ) -> Result<Event> {
      // Compute event ID (SHA256 hash)
      let event_id = event.compute_id()?;

      // Send hash to HSM for signing (key never leaves HSM!)
      let signature = signer.sign(event_id.as_bytes()).await?;

      // Return signed event
      Ok(Event {
          id: event_id,
          sig: signature,
          ..event
      })
  }

  Architecture Comparison

  Current (Encryption-based)

  ┌─────────────┐
  │   Browser   │
  └──────┬──────┘
         │ NIP-46 signing request
         ↓
  ┌─────────────────────────────────┐
  │     personal_bunker process     │
  │  ┌─────────────────────────┐   │
  │  │ Plaintext keys in RAM   │ ← VULNERABLE
  │  │ (after KMS decrypt)     │   │
  │  └─────────────────────────┘   │
  │           ↓                     │
  │  ┌─────────────────────────┐   │
  │  │ Sign with secp256k1     │   │
  │  └─────────────────────────┘   │
  └─────────────────────────────────┘

  HSM-based (Asymmetric Signing)

  ┌─────────────┐
  │   Browser   │
  └──────┬──────┘
         │ NIP-46 signing request
         ↓
  ┌─────────────────────────────────┐
  │     personal_bunker process     │
  │  ┌─────────────────────────┐   │
  │  │ Only has KMS key name   │ ← Just a reference
  │  └─────────────────────────┘   │
  │           ↓                     │
  │      Compute hash               │
  │           ↓                     │
  └───────────┼─────────────────────┘
              │ API call with hash
              ↓
      ┌──────────────────┐
      │   Cloud HSM      │
      │  ┌────────────┐  │
      │  │ Private    │  │ ← Key NEVER leaves
      │  │ Key        │  │
      │  └─────┬──────┘  │
      │        │         │
      │   Sign hash      │
      │        ↓         │
      │  ┌────────────┐  │
      │  │ Signature  │  │
      │  └────────────┘  │
      └────────┬─────────┘
               │ Return signature
               ↓
      ┌─────────────────┐
      │ personal_bunker │
      │ (builds Event)  │
      └─────────────────┘

  Benefits

  1. Security: Private key never exists outside HSM hardware (FIPS 140-2 Level 3)
  2. Compliance: Meets requirements for regulated environments
  3. Auditability: All signing operations logged by Cloud KMS
  4. No memory dumps: Even if attacker dumps process memory, no keys found

  Drawbacks

  1. Latency: ~50-100ms per signature (vs <1ms in-memory)
  2. Cost: HSM operations cost more (~$0.03 per 10k operations vs $0.03 per 10k decrypt operations)
  3. Complexity: More complex setup (need KMS key ring, IAM permissions, etc.)
  4. Can't import existing keys: HSM-generated keys can't be exported, so can't import user's existing nsec

  Implementation Checklist

  - Create new HsmSigner trait and implementation
  - Update personal_keys table schema (migration to add kms_key_name column)
  - Modify registration to create HSM keys instead of local keypairs
  - Update personal_bunker to use HsmSigner instead of Keys
  - Parse DER signatures from KMS into Nostr format
  - Handle HSM key creation errors gracefully
  - Add environment flag to choose HSM vs encryption mode
  - Write tests with HSM (requires real GCP setup, can't mock easily)
  - Update documentation about HSM requirements

  Hybrid Approach (Recommended)

  Support both modes via config:

  enum KeyMode {
      EncryptedInDb,  // Current: fast, less secure, can import existing keys
      HsmManaged,     // New: slower, very secure, HSM-generated only
  }

  // Let users choose based on their security/performance needs
  let mode = env::var("KEY_MODE").unwrap_or("encrypted");

  This would let you:
  - Use encryption for development/testing (faster, cheaper)
  - Use HSM for production/high-security users (slower, more secure)
  - Support importing existing nsec (only works with encryption mode)
