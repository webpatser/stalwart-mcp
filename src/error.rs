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
        }
    }
}
