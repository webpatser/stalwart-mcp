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

/// Build the message resource content for a specific email
pub async fn message_resource(
    manager: &Arc<AccountManager>,
    account: Option<&str>,
    email_id: &str,
) -> Result<String, crate::error::AppError> {
    let client = manager.get(account)?;
    let email = client.get_email(email_id).await?;

    serde_json::to_string_pretty(&email)
        .map_err(|e| crate::error::AppError::JmapRequest(e.to_string()))
}

/// Parsed resource URI variants
pub enum ResourceMatch<'a> {
    /// mail://accounts
    Accounts,
    /// mail://{account}/folders
    Folders { account: &'a str },
    /// mail://{account}/messages/{id}
    Message { account: &'a str, id: &'a str },
}

/// Parse a resource URI into a matched variant.
/// Returns `None` if the URI doesn't match any known pattern.
pub fn match_resource_uri(uri: &str) -> Option<ResourceMatch<'_>> {
    let path = uri.strip_prefix("mail://")?;

    if path == "accounts" {
        return Some(ResourceMatch::Accounts);
    }

    let (account, rest) = path.split_once('/')?;
    if account.is_empty() {
        return None;
    }

    if rest == "folders" {
        return Some(ResourceMatch::Folders { account });
    }

    let id = rest.strip_prefix("messages/")?;
    if !id.is_empty() {
        return Some(ResourceMatch::Message { account, id });
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_accounts() {
        let m = match_resource_uri("mail://accounts").unwrap();
        assert!(matches!(m, ResourceMatch::Accounts));
    }

    #[test]
    fn match_folders() {
        let m = match_resource_uri("mail://personal/folders").unwrap();
        assert!(matches!(
            m,
            ResourceMatch::Folders {
                account: "personal"
            }
        ));
    }

    #[test]
    fn match_message() {
        let m = match_resource_uri("mail://work/messages/abc123").unwrap();
        assert!(matches!(
            m,
            ResourceMatch::Message {
                account: "work",
                id: "abc123"
            }
        ));
    }

    #[test]
    fn match_message_with_special_id() {
        let m = match_resource_uri("mail://personal/messages/M-123_foo").unwrap();
        assert!(matches!(
            m,
            ResourceMatch::Message {
                account: "personal",
                id: "M-123_foo"
            }
        ));
    }

    #[test]
    fn rejects_invalid_uris() {
        assert!(match_resource_uri("").is_none());
        assert!(match_resource_uri("https://example.com").is_none());
        assert!(match_resource_uri("mail://").is_none());
        assert!(match_resource_uri("mail:///folders").is_none());
        assert!(match_resource_uri("mail://acc/unknown").is_none());
        assert!(match_resource_uri("mail://acc/messages/").is_none());
    }
}
