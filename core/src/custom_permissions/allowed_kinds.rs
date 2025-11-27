use crate::{
    traits::CustomPermission,
    types::permission::{Permission, PermissionError},
};
use async_trait::async_trait;
use nostr_sdk::{PublicKey, UnsignedEvent};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct AllowedKindsConfig {
    pub allowed_kinds: Option<Vec<u16>>,
}

pub struct AllowedKinds {
    config: AllowedKindsConfig,
}

#[async_trait]
impl CustomPermission for AllowedKinds {
    fn from_permission(
        permission: &Permission,
    ) -> Result<Box<dyn CustomPermission>, PermissionError> {
        let parsed_config: AllowedKindsConfig =
            serde_json::from_value(permission.config.0.clone())
                .map_err(|e| PermissionError::InvalidConfig(e.to_string()))?;

        Ok(Box::new(Self {
            config: parsed_config,
        }))
    }

    fn identifier(&self) -> &'static str {
        "allowed_kinds"
    }

    fn can_sign(&self, event: &UnsignedEvent) -> bool {
        match &self.config.allowed_kinds {
            None => true,
            Some(kinds) => kinds.contains(&event.kind.into()),
        }
    }

    // We don't get event info from these requests, so we must always allow
    fn can_encrypt(
        &self,
        _plaintext: &str,
        _sender_pubkey: &PublicKey,
        _recipient_pubkey: &PublicKey,
    ) -> bool {
        true
    }
    // We don't get event info from these requests, so we must always allow
    fn can_decrypt(
        &self,
        _ciphertext: &str,
        _sender_pubkey: &PublicKey,
        _recipient_pubkey: &PublicKey,
    ) -> bool {
        true
    }
}

#[test]
fn test_default() {
    let config = AllowedKindsConfig::default();
    assert!(config.allowed_kinds.is_none());
}
