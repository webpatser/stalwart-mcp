use crate::error::AppError;
use crate::jmap::JmapClient;
use jmap_client::core::query::Filter;
use jmap_client::core::response::{
    EmailSetResponse, EmailSubmissionSetResponse, TaggedMethodResponse,
};
use jmap_client::core::set::SetObject;
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
    /// From address for drafts; for `send_email` only the preferred identity.
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
        position: Option<i32>,
    ) -> Result<Vec<EmailSummary>, AppError> {
        // Step 1: Query for email IDs
        let mut request = self.client.build();

        let query = request
            .query_email()
            .account_id(&self.account_id)
            .sort([email::query::Comparator::received_at().descending()])
            .limit(limit);

        if let Some(pos) = position {
            query.position(pos);
        }

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

        let mut response = request
            .send_set_email()
            .await
            .map_err(|e| AppError::JmapRequest(e.to_string()))?;

        updated_one(&mut response, email_id)
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

        let mut response = request
            .send_set_email()
            .await
            .map_err(|e| AppError::JmapRequest(e.to_string()))?;

        updated_one(&mut response, email_id)
    }

    /// Bulk: set keyword + move to mailbox for multiple emails in one JMAP request
    pub async fn bulk_keyword_and_move(
        &self,
        email_ids: &[String],
        keyword: &str,
        keyword_set: bool,
        target_mailbox_id: &str,
    ) -> Result<usize, AppError> {
        let mut request = self.client.build();
        let set = request.set_email().account_id(&self.account_id);

        for id in email_ids {
            set.update(id)
                .keyword(keyword, keyword_set)
                .mailbox_ids([target_mailbox_id]);
        }

        let response = request
            .send_set_email()
            .await
            .map_err(|e| AppError::JmapRequest(e.to_string()))?;

        updated_count(&response)
    }

    /// Bulk: set a keyword on multiple emails in one JMAP request (no move)
    pub async fn bulk_keyword(
        &self,
        email_ids: &[String],
        keyword: &str,
        set: bool,
    ) -> Result<usize, AppError> {
        let mut request = self.client.build();
        let set_req = request.set_email().account_id(&self.account_id);

        for id in email_ids {
            set_req.update(id).keyword(keyword, set);
        }

        let response = request
            .send_set_email()
            .await
            .map_err(|e| AppError::JmapRequest(e.to_string()))?;

        updated_count(&response)
    }

    /// Bulk: permanently destroy multiple emails in one JMAP request
    pub async fn bulk_destroy(&self, email_ids: &[String]) -> Result<usize, AppError> {
        let mut request = self.client.build();
        let set = request.set_email().account_id(&self.account_id);

        set.destroy(email_ids);

        let mut response = request
            .send_set_email()
            .await
            .map_err(|e| AppError::JmapRequest(e.to_string()))?;

        destroyed_count(&mut response)
    }

    /// Create a draft email
    pub async fn create_draft(&self, compose: &ComposeEmail<'_>) -> Result<String, AppError> {
        // Find the Drafts mailbox
        let drafts_id = self
            .resolve_special_mailbox("Drafts")
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
        let create_id = creation_id(email.create_id())?;

        let mut response = request
            .send_set_email()
            .await
            .map_err(|e| AppError::JmapRequest(e.to_string()))?;

        created_email_id(&mut response, &create_id)
    }

    /// Send an email via EmailSubmission and return the server id of the copy
    /// stored in Sent (no `$draft` keyword). It is sent as the identity whose
    /// email matches `compose.from`, else the account's first identity, and
    /// that identity's address becomes the From header. If the submission is
    /// rejected, the stored copy is destroyed again.
    pub async fn send_email(&self, compose: &ComposeEmail<'_>) -> Result<String, AppError> {
        // Find the Sent mailbox
        let sent_id = self
            .resolve_special_mailbox("Sent")
            .await?
            .ok_or_else(|| AppError::NotFound("Sent mailbox not found".into()))?;

        // Get identity ID by listing all identities
        let mut request = self.client.build();
        request.get_identity();
        let identity_response = request
            .send_get_identity()
            .await
            .map_err(|e| AppError::JmapRequest(e.to_string()))?;

        let identities: Vec<SendingIdentity<'_>> = identity_response
            .list()
            .iter()
            .filter_map(|i| {
                Some(SendingIdentity {
                    id: i.id()?,
                    email: i.email()?,
                    name: i.name(),
                })
            })
            .collect();
        let identity = pick_identity(&identities, compose.from)
            .ok_or_else(|| AppError::JmapRequest("No identity found for sending".into()))?;

        let mut request = self.client.build();

        // Create the email in Sent. The From header is the identity's address:
        // the server matches the submission's sender against the identity, and
        // `compose.from` may be a plain login name.
        let email = request.set_email().account_id(&self.account_id).create();
        email
            .mailbox_ids([&sent_id])
            .keywords(["$seen"])
            .from([identity.sender_address()])
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
        let email_create_id = creation_id(email.create_id())?;

        // Create submission referencing the created email by its creation id
        let submission = request
            .set_email_submission()
            .account_id(&self.account_id)
            .create();

        submission
            .identity_id(identity.id)
            .email_id(format!("#{email_create_id}"));
        let submission_create_id = creation_id(submission.create_id())?;

        // Both method responses are needed: Email/set carries the email id,
        // EmailSubmission/set says whether it was actually submitted.
        // (send_set_email_submission would parse both as EmailSubmission/set.)
        let response = request
            .send()
            .await
            .map_err(|e| AppError::JmapRequest(e.to_string()))?;
        let (email_id, submitted) = split_send_responses(
            response.unwrap_method_responses(),
            &email_create_id,
            &submission_create_id,
        );
        let email_id = email_id?;

        if let Err(e) = submitted {
            // The copy in Sent was stored but never submitted: remove it.
            return Err(
                match self.bulk_destroy(std::slice::from_ref(&email_id)).await {
                    Ok(_) => e,
                    Err(cleanup) => AppError::JmapRequest(format!(
                        "{e}; the unsent copy {email_id} could not be removed from Sent: {cleanup}"
                    )),
                },
            );
        }

        Ok(email_id)
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

    /// Download raw RFC 5322 email bytes by email ID (via blob download)
    pub async fn get_email_raw(&self, email_id: &str) -> Result<Vec<u8>, AppError> {
        // First get the blob ID for this email
        let mut request = self.client.build();
        request
            .get_email()
            .account_id(&self.account_id)
            .ids([email_id])
            .properties([email::Property::BlobId]);

        let response = request
            .send_get_email()
            .await
            .map_err(|e| AppError::JmapRequest(e.to_string()))?;

        let blob_id = response
            .list()
            .first()
            .and_then(|e| e.blob_id())
            .ok_or_else(|| AppError::NotFound(format!("Email {email_id} not found")))?
            .to_string();

        // Download the raw email via JMAP blob download
        self.client
            .download(&blob_id)
            .await
            .map_err(|e| AppError::JmapRequest(format!("Blob download failed: {e}")))
    }

    /// Prefer the standard role so localized or renamed folders work too.
    async fn resolve_special_mailbox(&self, role: &str) -> Result<Option<String>, AppError> {
        let mailboxes = self.list_mailboxes().await?;
        Ok(special_mailbox_id(&mailboxes, role).map(str::to_owned))
    }

    /// Fetch blob IDs for a batch of email IDs in a single Email/get call.
    /// Returns (email_id, blob_id) pairs in the order returned by the server.
    /// Emails that can't be resolved are silently omitted from the result.
    pub async fn get_email_blob_ids(
        &self,
        email_ids: &[String],
    ) -> Result<Vec<(String, String)>, AppError> {
        let mut request = self.client.build();
        request
            .get_email()
            .account_id(&self.account_id)
            .ids(email_ids.iter().map(String::as_str))
            .properties([email::Property::Id, email::Property::BlobId]);

        let response = request
            .send_get_email()
            .await
            .map_err(|e| AppError::JmapRequest(e.to_string()))?;

        Ok(response
            .list()
            .iter()
            .filter_map(|e| {
                let id = e.id()?.to_string();
                let blob = e.blob_id()?.to_string();
                Some((id, blob))
            })
            .collect())
    }

    /// Resolve a mailbox name (e.g. "INBOX", "Drafts") to its ID
    pub async fn resolve_mailbox_id(&self, name: &str) -> Result<Option<String>, AppError> {
        let mailboxes = self.list_mailboxes().await?;
        Ok(mailboxes
            .into_iter()
            .find(|mb| mb.name.eq_ignore_ascii_case(name))
            .map(|mb| mb.id))
    }

    /// Resolve a mailbox by its JMAP role (e.g. "Inbox", "Junk", "Trash") to its ID
    pub async fn resolve_mailbox_by_role(&self, role: &str) -> Result<Option<String>, AppError> {
        let mailboxes = self.list_mailboxes().await?;
        Ok(mailboxes
            .into_iter()
            .find(|mb| mb.role.eq_ignore_ascii_case(role))
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

fn special_mailbox_id<'a>(mailboxes: &'a [MailboxInfo], role: &str) -> Option<&'a str> {
    mailboxes
        .iter()
        .find(|mb| mb.role.eq_ignore_ascii_case(role))
        .or_else(|| {
            mailboxes
                .iter()
                .find(|mb| mb.name.eq_ignore_ascii_case(role))
        })
        .map(|mb| mb.id.as_str())
}

fn creation_id(create_id: Option<String>) -> Result<String, AppError> {
    create_id.ok_or_else(|| AppError::JmapRequest("create request has no creation id".into()))
}

fn set_error(e: jmap_client::Error) -> AppError {
    AppError::JmapRequest(e.to_string())
}

/// Server-assigned id of an email created under `create_id`. The keys of the
/// `created` map are the client's creation ids (`c0`), not email ids.
fn created_email_id(response: &mut EmailSetResponse, create_id: &str) -> Result<String, AppError> {
    let id = response.created(create_id).map_err(set_error)?.take_id();
    non_empty_id(id, "Email/set")
}

/// Server-assigned id of an email submission created under `create_id`.
fn created_submission_id(
    response: &mut EmailSubmissionSetResponse,
    create_id: &str,
) -> Result<String, AppError> {
    let id = response.created(create_id).map_err(set_error)?.take_id();
    non_empty_id(id, "EmailSubmission/set")
}

/// A sending identity from `Identity/get`, reduced to what `send_email` needs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SendingIdentity<'a> {
    id: &'a str,
    email: &'a str,
    name: Option<&'a str>,
}

impl SendingIdentity<'_> {
    /// The From address: the identity's email, with its display name if set.
    fn sender_address(&self) -> email::EmailAddress {
        match self.name.filter(|n| !n.trim().is_empty()) {
            Some(name) => (name, self.email).into(),
            None => self.email.into(),
        }
    }
}

/// The identity whose email matches `preferred` (case-insensitive), else the
/// first one. `preferred` is often a login name, which matches no identity.
fn pick_identity<'a>(
    identities: &[SendingIdentity<'a>],
    preferred: &str,
) -> Option<SendingIdentity<'a>> {
    identities
        .iter()
        .find(|i| i.email.eq_ignore_ascii_case(preferred))
        .or_else(|| identities.first())
        .copied()
}

/// Split the `[Email/set, EmailSubmission/set]` responses of a send into the
/// created email id and the created submission id.
fn split_send_responses(
    responses: Vec<TaggedMethodResponse>,
    email_create_id: &str,
    submission_create_id: &str,
) -> (Result<String, AppError>, Result<String, AppError>) {
    let mut responses = responses.into_iter();
    let email_id = responses
        .next()
        .ok_or_else(|| AppError::JmapRequest("Email/set returned no response".into()))
        .and_then(|r| r.unwrap_set_email().map_err(set_error))
        .and_then(|mut r| created_email_id(&mut r, email_create_id));
    let submitted = responses
        .next()
        .ok_or_else(|| AppError::JmapRequest("EmailSubmission/set returned no response".into()))
        .and_then(|r| r.unwrap_set_email_submission().map_err(set_error))
        .and_then(|mut r| created_submission_id(&mut r, submission_create_id));
    (email_id, submitted)
}

fn non_empty_id(id: String, method: &str) -> Result<String, AppError> {
    if id.is_empty() {
        Err(AppError::JmapRequest(format!(
            "{method} created the object but returned no id"
        )))
    } else {
        Ok(id)
    }
}

/// Fail when the server rejected the update of `id` (`notUpdated`).
fn updated_one(response: &mut EmailSetResponse, id: &str) -> Result<(), AppError> {
    response.updated(id).map(|_| ()).map_err(set_error)
}

/// Number of emails updated; an error when none were and the server reported why.
fn updated_count(response: &EmailSetResponse) -> Result<usize, AppError> {
    let count = response.updated_ids().map_or(0, Iterator::count);
    if count == 0 {
        response.unwrap_update_errors().map_err(set_error)?;
    }
    Ok(count)
}

/// Number of emails destroyed; an error when none were and the server reported why.
fn destroyed_count(response: &mut EmailSetResponse) -> Result<usize, AppError> {
    let count = response.destroyed_ids().map_or(0, Iterator::count);
    if count == 0 {
        let rejected = response
            .not_destroyed_ids()
            .and_then(|mut ids| ids.next().cloned());
        if let Some(id) = rejected {
            response.destroyed(&id).map_err(|e| {
                AppError::JmapRequest(format!("Email/set destroy of {id} failed: {e}"))
            })?;
        }
    }
    Ok(count)
}

#[cfg(test)]
mod set_response_tests {
    use super::*;

    fn email_set(json: &str) -> EmailSetResponse {
        serde_json::from_str(json).expect("valid Email/set response")
    }

    #[test]
    fn created_email_id_is_the_server_id_not_the_creation_id() {
        let mut response = email_set(
            r#"{"accountId":"a","newState":"s1",
                "created":{"c0":{"id":"oueaaadvb","blobId":"b1","threadId":"t1","size":120}}}"#,
        );
        assert_eq!(
            created_email_id(&mut response, "c0").expect("created"),
            "oueaaadvb"
        );
    }

    #[test]
    fn created_email_id_reports_not_created() {
        let mut response = email_set(
            r#"{"accountId":"a","newState":"s1","created":null,
                "notCreated":{"c0":{"type":"invalidProperties","description":"bad from"}}}"#,
        );
        let err = created_email_id(&mut response, "c0").expect_err("not created");
        assert!(err.to_string().contains("bad from"), "{err}");
    }

    #[test]
    fn created_email_id_rejects_missing_id() {
        let mut response = email_set(r#"{"accountId":"a","newState":"s1","created":{"c0":{}}}"#);
        assert!(created_email_id(&mut response, "c0").is_err());
    }

    #[test]
    fn created_submission_id_is_the_server_id() {
        let mut response: EmailSubmissionSetResponse = serde_json::from_str(
            r#"{"accountId":"a","newState":"s1","created":{"c0":{"id":"sub-7"}}}"#,
        )
        .expect("valid EmailSubmission/set response");
        assert_eq!(
            created_submission_id(&mut response, "c0").expect("created"),
            "sub-7"
        );
    }

    fn send_responses(json: &str) -> Vec<TaggedMethodResponse> {
        serde_json::from_str::<jmap_client::core::response::Response<TaggedMethodResponse>>(json)
            .expect("valid JMAP response")
            .unwrap_method_responses()
    }

    const SENT: &str = r#"{"sessionState":"x","methodResponses":[
        ["Email/set",{"accountId":"a","newState":"s1",
            "created":{"c0":{"id":"m42","blobId":"b1","threadId":"t1","size":120}}},"s0"],
        ["EmailSubmission/set",{"accountId":"a","newState":"s2",
            "created":{"c0":{"id":"sub-7"}}},"s1"]]}"#;

    #[test]
    fn send_returns_the_email_id_not_the_submission_id() {
        let (email_id, submitted) = split_send_responses(send_responses(SENT), "c0", "c0");
        assert_eq!(email_id.expect("email"), "m42");
        assert_eq!(submitted.expect("submission"), "sub-7");
    }

    #[test]
    fn send_surfaces_a_rejected_submission() {
        let json = r#"{"sessionState":"x","methodResponses":[
            ["Email/set",{"accountId":"a","newState":"s1",
                "created":{"c0":{"id":"m42","blobId":"b1","threadId":"t1","size":120}}},"s0"],
            ["EmailSubmission/set",{"accountId":"a","newState":"s2","created":null,
                "notCreated":{"c0":{"type":"forbidden","description":"sender mismatch"}}},"s1"]]}"#;
        let (email_id, submitted) = split_send_responses(send_responses(json), "c0", "c0");
        assert_eq!(email_id.expect("email"), "m42");
        let err = submitted.expect_err("rejected");
        assert!(err.to_string().contains("sender mismatch"), "{err}");
    }

    #[test]
    fn send_surfaces_a_rejected_email_and_missing_responses() {
        let json = r#"{"sessionState":"x","methodResponses":[
            ["Email/set",{"accountId":"a","newState":"s1","created":null,
                "notCreated":{"c0":{"type":"invalidProperties","description":"bad from"}}},"s0"],
            ["error",{"type":"invalidArguments","description":"unresolved #c0"},"s1"]]}"#;
        let (email_id, submitted) = split_send_responses(send_responses(json), "c0", "c0");
        assert!(
            email_id
                .expect_err("rejected")
                .to_string()
                .contains("bad from")
        );
        assert!(submitted.is_err());

        let (email_id, submitted) = split_send_responses(Vec::new(), "c0", "c0");
        assert!(email_id.is_err() && submitted.is_err());
    }

    const ALICE: SendingIdentity<'static> = SendingIdentity {
        id: "i1",
        email: "alice@example.com",
        name: Some("Alice"),
    };
    const SALES: SendingIdentity<'static> = SendingIdentity {
        id: "i2",
        email: "sales@example.com",
        name: Some(" "),
    };

    #[test]
    fn identity_matches_the_preferred_address_else_the_first() {
        let ids = [ALICE, SALES];
        assert_eq!(pick_identity(&ids, "Sales@Example.com"), Some(SALES));
        // A plain login name matches no identity: fall back to the first.
        assert_eq!(pick_identity(&ids, "alice"), Some(ALICE));
        assert_eq!(pick_identity(&[], "alice"), None);
    }

    #[test]
    fn sender_address_is_the_identity_email() {
        let json = |a: email::EmailAddress| serde_json::to_value(a).expect("serializable");
        assert_eq!(
            json(ALICE.sender_address()),
            serde_json::json!({"name": "Alice", "email": "alice@example.com"})
        );
        assert_eq!(
            json(SALES.sender_address())["email"],
            serde_json::json!("sales@example.com")
        );
        assert!(json(SALES.sender_address())["name"].is_null());
    }

    #[test]
    fn creation_id_is_required() {
        assert_eq!(creation_id(Some("c0".into())).expect("id"), "c0");
        assert!(creation_id(None).is_err());
    }

    const REJECTED: &str = r#"{"accountId":"a","newState":"s1",
        "notUpdated":{"m1":{"type":"notFound"}},
        "notDestroyed":{"m1":{"type":"notFound","description":"no such email"}}}"#;

    const ACCEPTED: &str = r#"{"accountId":"a","newState":"s1",
        "updated":{"m1":null,"m2":null},"destroyed":["m3"]}"#;

    #[test]
    fn update_and_destroy_surface_server_rejections() {
        assert!(updated_one(&mut email_set(REJECTED), "m1").is_err());
        assert!(updated_count(&email_set(REJECTED)).is_err());
        let err = destroyed_count(&mut email_set(REJECTED)).expect_err("rejected");
        assert!(err.to_string().contains("m1"), "{err}");
    }

    #[test]
    fn update_and_destroy_count_what_the_server_accepted() {
        assert!(updated_one(&mut email_set(ACCEPTED), "m1").is_ok());
        assert_eq!(updated_count(&email_set(ACCEPTED)).expect("count"), 2);
        assert_eq!(destroyed_count(&mut email_set(ACCEPTED)).expect("count"), 1);
    }
}

#[cfg(test)]
mod special_mailbox_tests {
    use super::*;

    fn mailbox(id: &str, name: &str, role: &str) -> MailboxInfo {
        MailboxInfo {
            id: id.into(),
            name: name.into(),
            role: role.into(),
            total_emails: 0,
            unread_emails: 0,
            parent_id: None,
        }
    }

    #[test]
    fn role_precedes_name_for_drafts_and_sent() {
        for role in ["Drafts", "Sent"] {
            let mailboxes = vec![
                mailbox("name", role, "None"),
                mailbox("role", "Localized folder", &role.to_lowercase()),
            ];
            assert_eq!(special_mailbox_id(&mailboxes, role), Some("role"));
            assert_eq!(
                special_mailbox_id(&mailboxes[..1], &role.to_lowercase()),
                Some("name")
            );
            assert_eq!(special_mailbox_id(&[], role), None);
        }
    }
}
