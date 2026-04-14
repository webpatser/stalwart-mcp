use crate::error::AppError;
use crate::jmap::JmapClient;
use jmap_client::core::query::Filter;
use jmap_client::email;
use jmap_client::mailbox;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct MailboxInfo {
    pub id: String,
    pub name: String,
    pub role: String,
    pub total_emails: usize,
    pub unread_emails: usize,
    pub parent_id: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EmailSummary {
    pub id: String,
    pub subject: Option<String>,
    pub from: Vec<String>,
    pub to: Vec<String>,
    pub received_at: Option<i64>,
    pub is_unread: bool,
    pub is_flagged: bool,
    pub preview: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct EmailDetail {
    pub id: String,
    pub subject: Option<String>,
    pub from: Vec<String>,
    pub to: Vec<String>,
    pub cc: Vec<String>,
    pub received_at: Option<i64>,
    pub is_unread: bool,
    pub is_flagged: bool,
    pub text_body: Option<String>,
    pub html_body: Option<String>,
    pub attachments: Vec<AttachmentInfo>,
}

#[derive(Debug, Serialize)]
pub struct AttachmentInfo {
    pub name: Option<String>,
    pub content_type: Option<String>,
    pub size: usize,
}

#[derive(Debug, Default)]
pub struct SearchFilters<'a> {
    pub text: Option<&'a str>,
    pub from: Option<&'a str>,
    pub to: Option<&'a str>,
    pub subject: Option<&'a str>,
    pub mailbox_id: Option<&'a str>,
    pub after: Option<i64>,
    pub before: Option<i64>,
    pub has_attachment: Option<bool>,
    pub limit: usize,
}

#[derive(Debug, Default)]
pub struct ComposeEmail<'a> {
    pub from: &'a str,
    pub to: &'a [String],
    pub cc: &'a [String],
    pub subject: &'a str,
    pub body: &'a str,
    pub in_reply_to: Option<&'a str>,
    pub references: Option<&'a str>,
}

impl JmapClient {
    pub async fn list_mailboxes(&self) -> Result<Vec<MailboxInfo>, AppError> {
        let mut request = self.client.build();
        request
            .get_mailbox()
            .account_id(&self.account_id)
            .properties([
                mailbox::Property::Id,
                mailbox::Property::Name,
                mailbox::Property::Role,
                mailbox::Property::TotalEmails,
                mailbox::Property::UnreadEmails,
                mailbox::Property::ParentId,
            ]);

        let response = request
            .send_get_mailbox()
            .await
            .map_err(|e| AppError::JmapRequest(e.to_string()))?;

        let mailboxes = response
            .list()
            .iter()
            .map(|mb| MailboxInfo {
                id: mb.id().unwrap_or_default().to_string(),
                name: mb.name().unwrap_or_default().to_string(),
                role: format!("{:?}", mb.role()),
                total_emails: mb.total_emails(),
                unread_emails: mb.unread_emails(),
                parent_id: mb.parent_id().map(|s| s.to_string()),
            })
            .collect();

        Ok(mailboxes)
    }

    pub async fn list_recent_emails(
        &self,
        mailbox_id: Option<&str>,
        limit: usize,
        unread_only: bool,
        after: Option<i64>,
        before: Option<i64>,
    ) -> Result<Vec<EmailSummary>, AppError> {
        // Step 1: Query for email IDs
        let mut request = self.client.build();

        let query = request
            .query_email()
            .account_id(&self.account_id)
            .sort([email::query::Comparator::received_at().descending()])
            .limit(limit);

        let mut filters: Vec<email::query::Filter> = Vec::new();
        if let Some(mb_id) = mailbox_id {
            filters.push(email::query::Filter::in_mailbox(mb_id));
        }
        if unread_only {
            filters.push(email::query::Filter::not_keyword("$seen"));
        }
        if let Some(ts) = after {
            filters.push(email::query::Filter::after(ts));
        }
        if let Some(ts) = before {
            filters.push(email::query::Filter::before(ts));
        }

        if !filters.is_empty() {
            query.filter(Filter::and(filters));
        }

        let query_response = request
            .send_query_email()
            .await
            .map_err(|e| AppError::JmapRequest(e.to_string()))?;

        let ids: Vec<&str> = query_response.ids().iter().map(|s| s.as_str()).collect();
        if ids.is_empty() {
            return Ok(vec![]);
        }

        // Step 2: Fetch email details for those IDs
        let mut request = self.client.build();
        request
            .get_email()
            .account_id(&self.account_id)
            .ids(ids.iter().copied())
            .properties([
                email::Property::Id,
                email::Property::Subject,
                email::Property::From,
                email::Property::To,
                email::Property::ReceivedAt,
                email::Property::Keywords,
                email::Property::Preview,
            ]);

        let response = request
            .send_get_email()
            .await
            .map_err(|e| AppError::JmapRequest(e.to_string()))?;

        let emails = response.list().iter().map(email_to_summary).collect();

        Ok(emails)
    }

    pub async fn search_emails(
        &self,
        search: &SearchFilters<'_>,
    ) -> Result<Vec<EmailSummary>, AppError> {
        let mut request = self.client.build();

        let q = request
            .query_email()
            .account_id(&self.account_id)
            .sort([email::query::Comparator::received_at().descending()])
            .limit(search.limit);

        let mut filters: Vec<email::query::Filter> = Vec::new();
        if let Some(text) = search.text {
            filters.push(email::query::Filter::text(text));
        }
        if let Some(from) = search.from {
            filters.push(email::query::Filter::from(from));
        }
        if let Some(to) = search.to {
            filters.push(email::query::Filter::to(to));
        }
        if let Some(subject) = search.subject {
            filters.push(email::query::Filter::subject(subject));
        }
        if let Some(mb_id) = search.mailbox_id {
            filters.push(email::query::Filter::in_mailbox(mb_id));
        }
        if let Some(ts) = search.after {
            filters.push(email::query::Filter::after(ts));
        }
        if let Some(ts) = search.before {
            filters.push(email::query::Filter::before(ts));
        }
        if let Some(true) = search.has_attachment {
            filters.push(email::query::Filter::has_attachment(true));
        }

        match filters.len() {
            0 => {}
            1 => {
                q.filter(filters.into_iter().next().unwrap());
            }
            _ => {
                q.filter(Filter::and(filters));
            }
        }

        let query_response = request
            .send_query_email()
            .await
            .map_err(|e| AppError::JmapRequest(e.to_string()))?;

        let ids: Vec<&str> = query_response.ids().iter().map(|s| s.as_str()).collect();
        if ids.is_empty() {
            return Ok(vec![]);
        }

        let mut request = self.client.build();
        request
            .get_email()
            .account_id(&self.account_id)
            .ids(ids.iter().copied())
            .properties([
                email::Property::Id,
                email::Property::Subject,
                email::Property::From,
                email::Property::To,
                email::Property::ReceivedAt,
                email::Property::Keywords,
                email::Property::Preview,
            ]);

        let response = request
            .send_get_email()
            .await
            .map_err(|e| AppError::JmapRequest(e.to_string()))?;

        let emails = response.list().iter().map(email_to_summary).collect();

        Ok(emails)
    }

    /// Set or unset a keyword on an email
    pub async fn set_email_keyword(
        &self,
        email_id: &str,
        keyword: &str,
        set: bool,
    ) -> Result<(), AppError> {
        let mut request = self.client.build();
        request
            .set_email()
            .account_id(&self.account_id)
            .update(email_id)
            .keyword(keyword, set);

        request
            .send_set_email()
            .await
            .map_err(|e| AppError::JmapRequest(e.to_string()))?;

        Ok(())
    }

    /// Move an email to a different mailbox
    pub async fn move_email(
        &self,
        email_id: &str,
        target_mailbox_id: &str,
    ) -> Result<(), AppError> {
        let mut request = self.client.build();
        request
            .set_email()
            .account_id(&self.account_id)
            .update(email_id)
            .mailbox_ids([target_mailbox_id]);

        request
            .send_set_email()
            .await
            .map_err(|e| AppError::JmapRequest(e.to_string()))?;

        Ok(())
    }

    /// Create a draft email
    pub async fn create_draft(&self, compose: &ComposeEmail<'_>) -> Result<String, AppError> {
        // Find the Drafts mailbox
        let drafts_id = self
            .resolve_mailbox_id("Drafts")
            .await?
            .ok_or_else(|| AppError::NotFound("Drafts mailbox not found".into()))?;

        let mut request = self.client.build();
        let email = request.set_email().account_id(&self.account_id).create();

        email
            .mailbox_ids([&drafts_id])
            .keywords(["$draft", "$seen"])
            .from([compose.from])
            .to(compose.to.iter().map(|a| a.as_str()))
            .subject(compose.subject)
            .body_value("1".to_string(), compose.body)
            .text_body(email::EmailBodyPart::new().part_id("1"));

        if !compose.cc.is_empty() {
            email.cc(compose.cc.iter().map(|a| a.as_str()));
        }
        if let Some(irt) = compose.in_reply_to {
            email.in_reply_to([irt]);
        }
        if let Some(refs) = compose.references {
            email.references([refs]);
        }

        let response = request
            .send_set_email()
            .await
            .map_err(|e| AppError::JmapRequest(e.to_string()))?;

        let created_id = response
            .created_ids()
            .and_then(|mut ids| ids.next().map(|s| s.to_string()))
            .ok_or_else(|| AppError::JmapRequest("Failed to create draft".into()))?;

        Ok(created_id)
    }

    /// Send an email via EmailSubmission
    pub async fn send_email(&self, compose: &ComposeEmail<'_>) -> Result<String, AppError> {
        // Find the Sent mailbox
        let sent_id = self
            .resolve_mailbox_id("Sent")
            .await?
            .ok_or_else(|| AppError::NotFound("Sent mailbox not found".into()))?;

        // Get identity ID by listing all identities
        let mut request = self.client.build();
        request.get_identity();
        let identity_response = request
            .send_get_identity()
            .await
            .map_err(|e| AppError::JmapRequest(e.to_string()))?;

        let identity_id = identity_response
            .list()
            .first()
            .and_then(|i| i.id())
            .ok_or_else(|| AppError::JmapRequest("No identity found for sending".into()))?
            .to_string();

        let mut request = self.client.build();

        // Create the email in Sent
        let email = request.set_email().account_id(&self.account_id).create();
        email
            .mailbox_ids([&sent_id])
            .keywords(["$seen"])
            .from([compose.from])
            .to(compose.to.iter().map(|a| a.as_str()))
            .subject(compose.subject)
            .body_value("1".to_string(), compose.body)
            .text_body(email::EmailBodyPart::new().part_id("1"));

        if !compose.cc.is_empty() {
            email.cc(compose.cc.iter().map(|a| a.as_str()));
        }
        if let Some(irt) = compose.in_reply_to {
            email.in_reply_to([irt]);
        }
        if let Some(refs) = compose.references {
            email.references([refs]);
        }

        // Create submission referencing the created email
        let submission = request
            .set_email_submission()
            .account_id(&self.account_id)
            .create();

        submission.identity_id(&identity_id).email_id("#c0"); // backreference to created email

        // Use send_set_email_submission which processes the batch
        let response = request
            .send_set_email_submission()
            .await
            .map_err(|e| AppError::JmapRequest(e.to_string()))?;

        // The submission was created successfully if we get here
        let created_id = response
            .created_ids()
            .and_then(|mut ids| ids.next().map(|s| s.to_string()))
            .unwrap_or_else(|| "sent".to_string());

        Ok(created_id)
    }

    /// Get the Message-ID header of an email (for reply threading)
    pub async fn get_message_id(&self, email_id: &str) -> Result<Option<String>, AppError> {
        let mut request = self.client.build();
        request
            .get_email()
            .account_id(&self.account_id)
            .ids([email_id])
            .properties([email::Property::MessageId]);

        let response = request
            .send_get_email()
            .await
            .map_err(|e| AppError::JmapRequest(e.to_string()))?;

        Ok(response
            .list()
            .first()
            .and_then(|e| e.message_id())
            .and_then(|ids| ids.first())
            .map(|s| s.to_string()))
    }

    pub async fn get_email(&self, email_id: &str) -> Result<EmailDetail, AppError> {
        let mut request = self.client.build();

        request
            .get_email()
            .account_id(&self.account_id)
            .ids([email_id])
            .properties([
                email::Property::Id,
                email::Property::Subject,
                email::Property::From,
                email::Property::To,
                email::Property::Cc,
                email::Property::ReceivedAt,
                email::Property::Keywords,
                email::Property::BodyValues,
                email::Property::TextBody,
                email::Property::HtmlBody,
                email::Property::Attachments,
            ])
            .arguments()
            .fetch_all_body_values(true);

        let response = request
            .send_get_email()
            .await
            .map_err(|e| AppError::JmapRequest(e.to_string()))?;

        let email = response.list().first().ok_or_else(|| {
            tracing::debug!(email_id = %email_id, "Email not found");
            AppError::NotFound("Email not found".into())
        })?;

        Ok(email_to_detail(email))
    }

    /// Resolve a mailbox name (e.g. "INBOX", "Drafts") to its ID
    pub async fn resolve_mailbox_id(&self, name: &str) -> Result<Option<String>, AppError> {
        let mailboxes = self.list_mailboxes().await?;
        Ok(mailboxes
            .into_iter()
            .find(|mb| mb.name.eq_ignore_ascii_case(name))
            .map(|mb| mb.id))
    }
}

fn email_to_summary(e: &email::Email) -> EmailSummary {
    let keywords = e.keywords();
    EmailSummary {
        id: e.id().unwrap_or_default().to_string(),
        subject: e.subject().map(|s| s.to_string()),
        from: extract_addresses(e.from()),
        to: extract_addresses(e.to()),
        received_at: e.received_at(),
        is_unread: !keywords.contains(&"$seen"),
        is_flagged: keywords.contains(&"$flagged"),
        preview: e.preview().map(|s| s.to_string()),
    }
}

fn email_to_detail(e: &email::Email) -> EmailDetail {
    let keywords = e.keywords();

    let text_body = e
        .text_body()
        .and_then(|parts| parts.first())
        .and_then(|part| part.part_id())
        .and_then(|id| e.body_value(id))
        .map(|bv| bv.value().to_string());

    let html_body = e
        .html_body()
        .and_then(|parts| parts.first())
        .and_then(|part| part.part_id())
        .and_then(|id| e.body_value(id))
        .map(|bv| bv.value().to_string());

    let attachments = e
        .attachments()
        .unwrap_or_default()
        .iter()
        .map(|part| AttachmentInfo {
            name: part.name().map(|s| s.to_string()),
            content_type: part.content_type().map(|s| s.to_string()),
            size: part.size(),
        })
        .collect();

    EmailDetail {
        id: e.id().unwrap_or_default().to_string(),
        subject: e.subject().map(|s| s.to_string()),
        from: extract_addresses(e.from()),
        to: extract_addresses(e.to()),
        cc: extract_addresses(e.cc()),
        received_at: e.received_at(),
        is_unread: !keywords.contains(&"$seen"),
        is_flagged: keywords.contains(&"$flagged"),
        text_body,
        html_body,
        attachments,
    }
}

fn extract_addresses(addrs: Option<&[email::EmailAddress]>) -> Vec<String> {
    addrs
        .unwrap_or_default()
        .iter()
        .map(|a| match a.name() {
            Some(name) => format!("{name} <{}>", a.email()),
            None => a.email().to_string(),
        })
        .collect()
}
