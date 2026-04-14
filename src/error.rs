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
        match &err {
            AppError::NotFound(_) => ErrorData::resource_not_found(err.to_string(), None),
            _ => ErrorData::internal_error(err.to_string(), None),
        }
    }
}
