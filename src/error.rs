use thiserror::Error;

#[derive(Debug, Error)]
pub enum PairError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("iroh error: {0}")]
    Iroh(String),
    #[error("crypto error: {0}")]
    Crypto(String),
    #[error("framing error: {0}")]
    Framing(String),
    #[error("handshake failed: {0}")]
    Handshake(String),
    #[error("sas mismatch")]
    SasMismatch,
    #[error("timed out after {0:?}")]
    Timeout(std::time::Duration),
    #[error("pairing not enabled")]
    NotEnabled,
    #[error("channel closed")]
    ChannelClosed,
    #[error("serialization error: {0}")]
    Serde(#[from] serde_json::Error),
}

pub type Result<T> = std::result::Result<T, PairError>;
