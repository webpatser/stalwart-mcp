use crate::mcp::StalwartMcp;
use rmcp::handler::server::wrapper::Parameters;
use rmcp::model::{PromptMessage, PromptMessageRole};
use rmcp::{prompt, prompt_router};
use schemars::JsonSchema;
use serde::Deserialize;

#[derive(Debug, Deserialize, JsonSchema)]
pub struct DraftReplyArgs {
    /// The email message ID to reply to
    pub message_id: String,
    /// Account name to use. Omit for the default account.
    pub account: Option<String>,
    /// Tone for the reply: formal, casual, or brief (default: formal)
    pub tone: Option<String>,
}

#[derive(Debug, Deserialize, JsonSchema)]
pub struct SearchSummarizeArgs {
    /// Search query (e.g. "invoice from Acme", "meeting agenda")
    pub query: String,
    /// Account name to use. Omit for the default account.
    pub account: Option<String>,
}

#[prompt_router]
impl StalwartMcp {
    pub(crate) fn create_prompt_router() -> rmcp::handler::server::router::prompt::PromptRouter<Self>
    {
        Self::prompt_router()
    }

    /// Triage your inbox: summarize unread emails, flag important ones, suggest actions.
    #[prompt(
        name = "triage_inbox",
        description = "Summarize unread emails, flag what's important, suggest actions"
    )]
    async fn triage_inbox(&self) -> Vec<PromptMessage> {
        vec![
            PromptMessage::new_text(
                PromptMessageRole::User,
                "Triage my inbox. Show me what needs attention.".to_string(),
            ),
            PromptMessage::new_text(
                PromptMessageRole::Assistant,
                concat!(
                    "I'll triage your inbox now. Here's my approach:\n\n",
                    "1. First, I'll fetch your recent unread emails using `mail_list_recent` with `unread_only: true`\n",
                    "2. For each email, I'll assess urgency based on sender, subject, and age\n",
                    "3. I'll group them into:\n",
                    "   - **Action required** — needs a reply or decision\n",
                    "   - **FYI** — informational, can be read later\n",
                    "   - **Low priority** — newsletters, notifications, can be archived\n",
                    "4. For action-required emails, I'll suggest next steps\n",
                    "5. I can flag important ones or archive low-priority ones if you'd like\n\n",
                    "Let me start by listing your unread messages."
                )
                .to_string(),
            ),
        ]
    }

    /// Draft a reply to a specific email, with optional tone control.
    #[prompt(
        name = "draft_reply",
        description = "Draft a contextual reply to an email"
    )]
    async fn draft_reply(
        &self,
        Parameters(args): Parameters<DraftReplyArgs>,
    ) -> Vec<PromptMessage> {
        let tone = args.tone.as_deref().unwrap_or("formal");
        let account_hint = args
            .account
            .as_deref()
            .map(|a| format!(" (account: {a})"))
            .unwrap_or_default();

        vec![
            PromptMessage::new_text(
                PromptMessageRole::User,
                format!(
                    "Draft a {tone} reply to message ID: {}{account_hint}",
                    args.message_id
                ),
            ),
            PromptMessage::new_text(
                PromptMessageRole::Assistant,
                format!(
                    concat!(
                        "I'll draft a {tone} reply. Here's my approach:\n\n",
                        "1. First, I'll fetch the original message using `mail_get` with ID `{id}`{account}\n",
                        "2. I'll read the full conversation thread for context\n",
                        "3. I'll compose a {tone} reply that:\n",
                        "   - Addresses the key points raised\n",
                        "   - Matches the {tone} tone you requested\n",
                        "   - Keeps it concise and actionable\n",
                        "4. I'll save it as a draft using `mail_draft` so you can review before sending\n\n",
                        "Let me fetch the original message first."
                    ),
                    tone = tone,
                    id = args.message_id,
                    account = account_hint,
                ),
            ),
        ]
    }

    /// Search for emails and provide a structured summary of the results.
    #[prompt(
        name = "search_and_summarize",
        description = "Search emails and summarize results"
    )]
    async fn search_and_summarize(
        &self,
        Parameters(args): Parameters<SearchSummarizeArgs>,
    ) -> Vec<PromptMessage> {
        let account_hint = args
            .account
            .as_deref()
            .map(|a| format!(" in account '{a}'"))
            .unwrap_or_default();

        vec![
            PromptMessage::new_text(
                PromptMessageRole::User,
                format!(
                    "Search for \"{}\"{account_hint} and summarize what you find.",
                    args.query
                ),
            ),
            PromptMessage::new_text(
                PromptMessageRole::Assistant,
                format!(
                    concat!(
                        "I'll search and summarize. Here's my approach:\n\n",
                        "1. Search for emails matching \"{query}\"{account} using `mail_search`\n",
                        "2. For relevant results, fetch full content with `mail_get`\n",
                        "3. Present findings organized by:\n",
                        "   - **Timeline** — when the key exchanges happened\n",
                        "   - **Key points** — decisions, commitments, action items\n",
                        "   - **People involved** — who said what\n",
                        "   - **Attachments** — any relevant documents referenced\n",
                        "4. Highlight anything that still needs follow-up\n\n",
                        "Let me search now."
                    ),
                    query = args.query,
                    account = account_hint,
                ),
            ),
        ]
    }
}
