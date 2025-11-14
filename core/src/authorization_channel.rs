use tokio::sync::mpsc;

/// Channel types for authorization lifecycle management
pub type AuthorizationSender = mpsc::Sender<AuthorizationCommand>;
pub type AuthorizationReceiver = mpsc::Receiver<AuthorizationCommand>;

/// Buffer size for authorization command channel
/// 100 is plenty for typical rate of 1-10 authorizations per minute
pub const CHANNEL_BUFFER_SIZE: usize = 100;

/// Commands for managing authorization lifecycle in the signer daemon
#[derive(Debug, Clone)]
pub enum AuthorizationCommand {
    /// Add or update a single authorization
    /// Signer will load from database by bunker_pubkey
    Upsert {
        bunker_pubkey: String,
        tenant_id: i64,
        is_oauth: bool,
    },

    /// Remove an authorization (e.g., after revocation)
    Remove { bunker_pubkey: String },

    /// Full reload from database (e.g., after migration or manual trigger)
    ReloadAll,
}

/// Create a new authorization command channel
pub fn create_channel() -> (AuthorizationSender, AuthorizationReceiver) {
    mpsc::channel(CHANNEL_BUFFER_SIZE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_channel_send_receive() {
        let (tx, mut rx) = create_channel();
        let cmd = AuthorizationCommand::Upsert {
            bunker_pubkey: "test123".to_string(),
            tenant_id: 1,
            is_oauth: true,
        };
        tx.send(cmd).await.unwrap();
        let received = rx.recv().await.unwrap();
        assert!(matches!(received, AuthorizationCommand::Upsert { .. }));
    }

    #[tokio::test]
    async fn test_channel_close() {
        let (tx, mut rx) = create_channel();
        drop(tx);
        assert!(rx.recv().await.is_none());
    }

    #[test]
    fn test_buffer_size() {
        assert_eq!(CHANNEL_BUFFER_SIZE, 100);
    }
}
