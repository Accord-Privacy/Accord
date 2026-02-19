use thiserror::Error;

/// Errors that can occur when using the Accord Bot SDK.
#[derive(Debug, Error)]
pub enum BotError {
    #[error("WebSocket error: {0}")]
    WebSocket(#[from] tokio_tungstenite::tungstenite::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("JSON error: {0}")]
    Json(#[from] serde_json::Error),

    #[error("URL parse error: {0}")]
    Url(#[from] url::ParseError),

    #[error("Not connected")]
    NotConnected,

    #[error("Authentication failed: {0}")]
    AuthFailed(String),

    #[error("API error ({code}): {message}")]
    Api { code: u16, message: String },

    #[error("{0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, BotError>;
