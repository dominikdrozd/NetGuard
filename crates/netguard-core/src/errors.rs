use thiserror::Error;

#[derive(Debug, Error)]
pub enum NetGuardError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("TOML parse error: {0}")]
    TomlParse(#[from] toml::de::Error),

    #[error("Config error: {0}")]
    Config(String),

    #[error("Rule not found: {0}")]
    RuleNotFound(uuid::Uuid),

    #[error("Packet parse error: {0}")]
    PacketParse(String),

    #[error("NFQUEUE error: {0}")]
    NfQueue(String),

    #[error("Process lookup error: {0}")]
    ProcessLookup(String),

    #[error("Permission denied: {0}")]
    PermissionDenied(String),

    #[error("{0}")]
    Other(String),
}
