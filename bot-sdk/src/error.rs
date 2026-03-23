use thiserror::Error;

/// Errors that can occur when using the Accord Bot SDK.
#[derive(Debug, Error)]
pub enum BotError {
    #[error("WebSocket error: {0}")]
    WebSocket(Box<tokio_tungstenite::tungstenite::Error>),

    #[error("HTTP error: {0}")]
    Http(Box<reqwest::Error>),

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

impl From<tokio_tungstenite::tungstenite::Error> for BotError {
    fn from(e: tokio_tungstenite::tungstenite::Error) -> Self {
        BotError::WebSocket(Box::new(e))
    }
}

impl From<reqwest::Error> for BotError {
    fn from(e: reqwest::Error) -> Self {
        BotError::Http(Box::new(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── Display impl ────────────────────────────────────────────────────

    #[test]
    fn display_not_connected() {
        let err = BotError::NotConnected;
        assert_eq!(err.to_string(), "Not connected");
    }

    #[test]
    fn display_auth_failed() {
        let err = BotError::AuthFailed("invalid token".into());
        assert_eq!(err.to_string(), "Authentication failed: invalid token");
    }

    #[test]
    fn display_api_error() {
        let err = BotError::Api {
            code: 403,
            message: "Forbidden".into(),
        };
        assert_eq!(err.to_string(), "API error (403): Forbidden");
    }

    #[test]
    fn display_other() {
        let err = BotError::Other("something broke".into());
        assert_eq!(err.to_string(), "something broke");
    }

    #[test]
    fn display_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("not json").unwrap_err();
        let err = BotError::Json(json_err);
        assert!(err.to_string().starts_with("JSON error:"));
    }

    #[test]
    fn display_url_parse_error() {
        let url_err = url::Url::parse("://bad").unwrap_err();
        let err = BotError::Url(url_err);
        assert!(err.to_string().starts_with("URL parse error:"));
    }

    #[test]
    fn display_websocket_error() {
        let ws_err = tokio_tungstenite::tungstenite::Error::ConnectionClosed;
        let err = BotError::WebSocket(Box::new(ws_err));
        assert!(err.to_string().starts_with("WebSocket error:"));
    }

    // ── From conversions ────────────────────────────────────────────────

    #[test]
    fn from_serde_json_error() {
        let json_err = serde_json::from_str::<serde_json::Value>("{bad}").unwrap_err();
        let err: BotError = json_err.into();
        assert!(matches!(err, BotError::Json(_)));
    }

    #[test]
    fn from_url_parse_error() {
        let url_err = url::Url::parse("://").unwrap_err();
        let err: BotError = url_err.into();
        assert!(matches!(err, BotError::Url(_)));
    }

    #[test]
    fn from_tungstenite_error() {
        let ws_err = tokio_tungstenite::tungstenite::Error::ConnectionClosed;
        let err: BotError = ws_err.into();
        assert!(matches!(err, BotError::WebSocket(_)));
    }

    // ── Debug is implemented ────────────────────────────────────────────

    #[test]
    fn all_variants_are_debug() {
        // Ensures Debug derive works for every variant
        let variants: Vec<BotError> = vec![
            BotError::WebSocket(Box::new(
                tokio_tungstenite::tungstenite::Error::ConnectionClosed,
            )),
            BotError::Json(serde_json::from_str::<()>("x").unwrap_err()),
            BotError::Url(url::Url::parse("://").unwrap_err()),
            BotError::NotConnected,
            BotError::AuthFailed("fail".into()),
            BotError::Api {
                code: 500,
                message: "Internal".into(),
            },
            BotError::Other("misc".into()),
        ];
        for v in &variants {
            // Debug output should be non-empty
            assert!(!format!("{:?}", v).is_empty());
        }
    }
}
