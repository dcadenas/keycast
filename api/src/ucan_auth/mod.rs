// ABOUTME: UCAN-based authentication using user-signed capability tokens
// ABOUTME: Replaces server-signed JWT with user-signed UCAN for decentralized auth

mod did;
mod key_material;
mod validation;

pub use did::{nostr_pubkey_to_did, did_to_nostr_pubkey};
pub use key_material::NostrKeyMaterial;
pub use validation::{validate_ucan_token, extract_user_from_ucan};
