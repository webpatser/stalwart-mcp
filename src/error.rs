use rmcp::ErrorData;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum AppError {
    #[error("JMAP connection failed: {0}")]
    JmapConnection(String),

    #[error("JMAP request failed: {0}")]
    JmapRequest(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Authentication failed: {0}")]
    Auth(String),

    #[error("Resource not found: {0}")]
    NotFound(String),

    /// The server answered but refused the call or one of its objects (a JMAP
    /// method-level error or a SetError). Carries the server's own reason, which
    /// is passed on to the MCP client so it can act on it (for example a quota).
    #[error("Rejected by the server: {0}")]
    Rejected(String),

    /// This server refused the call itself, before asking the upstream server
    /// (a local safety check). The reason is passed on to the MCP client.
    #[error("Refused: {0}")]
    Refused(String),
}

impl From<AppError> for ErrorData {
    fn from(err: AppError) -> Self {
        tracing::warn!(error = %err, "Tool error");
        match err {
            AppError::NotFound(msg) => ErrorData::resource_not_found(msg, None),
            AppError::Auth(_) => ErrorData::invalid_request("Authentication failed", None),
            AppError::Config(_) => ErrorData::internal_error("Server misconfigured", None),
            AppError::JmapConnection(_) => {
                ErrorData::internal_error("Upstream connection failed", None)
            }
            AppError::JmapRequest(_) => ErrorData::internal_error("Upstream request failed", None),
            AppError::Rejected(msg) => {
                ErrorData::invalid_request(format!("Rejected by the server: {msg}"), None)
            }
            AppError::Refused(msg) => ErrorData::invalid_request(format!("Refused: {msg}"), None),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejected_passes_the_server_reason_to_the_client() {
        let data = ErrorData::from(AppError::Rejected(
            "x:MaskedEmail/set create: overQuota: too many".into(),
        ));
        assert!(data.message.contains("overQuota: too many"), "{data:?}");
    }

    #[test]
    fn refused_is_not_attributed_to_the_server() {
        let data = ErrorData::from(AppError::Refused("reserved name".into()));
        assert!(data.message.contains("Refused: reserved name"), "{data:?}");
        assert!(!data.message.contains("by the server"), "{data:?}");
    }

    #[test]
    fn request_failures_stay_opaque() {
        let data = ErrorData::from(AppError::JmapRequest("secret detail".into()));
        assert!(!data.message.contains("secret detail"));
    }
}
