use crate::jmap::AccountManager;
use futures::StreamExt;
use jmap_client::DataType;
use jmap_client::event_source::PushNotification;
use rmcp::model::{Notification, ResourceUpdatedNotificationParam, ServerNotification};
use rmcp::service::{Peer, RoleServer};
use std::sync::Arc;
use std::time::Duration;

const DEBOUNCE_DURATION: Duration = Duration::from_secs(2);

/// Listen to JMAP EventSource streams for all connected accounts
/// and forward state changes as MCP ResourceUpdatedNotifications.
/// Events are debounced: rapid changes within 2 seconds are collapsed into one notification.
pub async fn listen(accounts: Arc<AccountManager>, peer: Peer<RoleServer>, ping_interval: u32) {
    let account_list: Vec<(String, Arc<crate::jmap::JmapClient>)> = accounts
        .list()
        .into_iter()
        .map(|(name, client)| (name.to_string(), Arc::clone(client)))
        .collect();

    for (account_name, client) in account_list {
        let peer = peer.clone();

        tokio::spawn(async move {
            tracing::info!(account = %account_name, "Starting EventSource listener");

            let mut stream = match client.event_source(ping_interval).await {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(
                        account = %account_name,
                        error = %e,
                        "Failed to start EventSource, notifications disabled for this account"
                    );
                    return;
                }
            };

            let mut pending = false;
            let debounce = tokio::time::sleep(DEBOUNCE_DURATION);
            tokio::pin!(debounce);

            loop {
                tokio::select! {
                    event = stream.next() => {
                        match event {
                            Some(Ok(PushNotification::StateChange(changes))) => {
                                let has_email_change = changes.has_type(DataType::Email)
                                    || changes.has_type(DataType::EmailDelivery)
                                    || changes.has_type(DataType::Mailbox);

                                if has_email_change {
                                    // Reset debounce timer on each new event
                                    pending = true;
                                    debounce.as_mut().reset(tokio::time::Instant::now() + DEBOUNCE_DURATION);
                                }
                            }
                            Some(Ok(PushNotification::CalendarAlert(_))) => {}
                            Some(Err(e)) => {
                                tracing::warn!(
                                    account = %account_name,
                                    error = %e,
                                    "EventSource error"
                                );
                                break;
                            }
                            None => {
                                tracing::info!(account = %account_name, "EventSource stream ended");
                                break;
                            }
                        }
                    }
                    () = &mut debounce, if pending => {
                        pending = false;

                        tracing::info!(
                            event = "email_activity",
                            account = %account_name,
                            "Email state change detected, notifying MCP client"
                        );

                        let notification = ServerNotification::ResourceUpdatedNotification(
                            Notification::new(ResourceUpdatedNotificationParam::new(format!(
                                "stalwart://inbox/{account_name}"
                            ))),
                        );

                        if let Err(e) = peer.send_notification(notification).await {
                            tracing::warn!(
                                error = %e,
                                "Failed to send MCP notification, client may have disconnected"
                            );
                            return;
                        }
                    }
                }
            }

            tracing::info!(account = %account_name, "EventSource listener stopped");
        });
    }
}
