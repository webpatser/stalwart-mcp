use crate::jmap::AccountManager;
use std::sync::Arc;

/// Build the accounts resource content (list of all configured accounts)
pub async fn accounts_resource(
    manager: &Arc<AccountManager>,
) -> Result<String, crate::error::AppError> {
    let default_name = manager.default_name();
    let accounts: Vec<_> = manager
        .list()
        .iter()
        .map(|(name, client)| {
            serde_json::json!({
                "name": name,
                "id": client.account_id(),
                "username": client.username(),
                "is_default": *name == default_name,
            })
        })
        .collect();

    serde_json::to_string_pretty(&accounts)
        .map_err(|e| crate::error::AppError::JmapRequest(e.to_string()))
}

/// Build the folders resource content for an account
pub async fn folders_resource(
    manager: &Arc<AccountManager>,
    account: Option<&str>,
) -> Result<String, crate::error::AppError> {
    let client = manager.get(account)?;
    let mailboxes = client.list_mailboxes().await?;

    serde_json::to_string_pretty(&mailboxes)
        .map_err(|e| crate::error::AppError::JmapRequest(e.to_string()))
}
