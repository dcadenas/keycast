use crate::{
    traits::CustomPermission,
    types::permission::{Permission, PermissionError},
};
use async_trait::async_trait;
use nostr_sdk::{PublicKey, UnsignedEvent};
use serde::{Deserialize, Serialize};

#[derive(Debug, Serialize, Deserialize, Clone, Default)]
pub struct ContentFilterConfig {
    pub blocked_words: Option<Vec<String>>,
}

pub struct ContentFilter {
    config: ContentFilterConfig,
}

#[async_trait]
impl CustomPermission for ContentFilter {
    fn from_permission(
        permission: &Permission,
    ) -> Result<Box<dyn CustomPermission>, PermissionError> {
        let parsed_config: ContentFilterConfig = serde_json::from_value(permission.config.0.clone())
            .map_err(|e| PermissionError::InvalidConfig(e.to_string()))?;

        Ok(Box::new(Self {
            config: parsed_config,
        }))
    }

    fn identifier(&self) -> &'static str {
        "content_filter"
    }

    fn can_sign(&self, event: &UnsignedEvent) -> bool {
        match &self.config.blocked_words {
            None => true,
            Some(words) => !words.iter().any(|word| event.content.contains(word)),
        }
    }

    fn can_encrypt(
        &self,
        plaintext: &str,
        _sender_pubkey: &PublicKey,
        _recipient_pubkey: &PublicKey,
    ) -> bool {
        match &self.config.blocked_words {
            None => true,
            Some(words) => !words.iter().any(|word| plaintext.contains(word)),
        }
    }

    // We can't know what is in the content of the event, so we always allow decryption
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
    let config = ContentFilterConfig::default();
    assert!(config.blocked_words.is_none());
}
