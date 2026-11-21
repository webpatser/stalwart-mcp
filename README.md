# stalwart-mcp

A Rust-based [MCP](https://modelcontextprotocol.io/) server for [Stalwart Mail Server](https://stalw.art/). It lets AI assistants access mail via JMAP while keeping your data under your own jurisdiction.

## Why

Existing Gmail and Outlook MCP servers route queries through Google/Microsoft APIs. With stalwart-mcp, AI queries hit **your** Stalwart instance directly. Mail data never leaves your infrastructure; only the AI questions and answers go to the LLM provider.

## Tools

### Read
| Tool | Description |
|------|-------------|
| `mail_list_folders` | List mailboxes with message counts |
| `mail_list_recent` | Recent emails, filtered by folder, date range, unread |
| `mail_search` | Search by full-text, sender, recipient, subject, date, attachments |
| `mail_get` | Full message content with attachment metadata |

### Write
| Tool | Description |
|------|-------------|
| `mail_flag` | Mark as read/unread/flagged/unflagged/junk/notjunk (junk auto-moves to Junk folder) |
| `mail_move` | Move to folder (Archive, Trash, etc.) |
| `mail_bulk_junk` | Bulk mark emails as junk/notjunk in a single JMAP request |
| `mail_bulk_delete` | Permanently delete multiple emails in a single JMAP request |
| `mail_bulk_read` | Bulk mark emails as read in a single JMAP request |
| `mail_draft` | Save draft in Drafts folder |
| `mail_send` | Send email (requires `capabilities.send = true` in config) |
| `spam_train` | Train Stalwart's Bayes classifier via JMAP `SpamTrainingSample/set` (requires Stalwart v0.16+ and `capabilities.spam_training = true`) |

### Account

| Tool | Description |
|------|-------------|
| `mail_masked_list` | List masked email addresses (Stalwart 1.1+, `x:MaskedEmail/get`) |
| `mail_masked_create` | Create a server-generated masked address, optionally with a prefix, domain, description, site and expiry (requires `capabilities.masked_email = true`; the server limits the number per account) |
| `mail_masked_disable` | Disable a masked address so mail to it is no longer delivered (requires `capabilities.masked_email = true`) |
| `mail_vacation_get` | Get the vacation response (out-of-office auto-reply) |
| `mail_vacation_set` | Replace the whole vacation response; omitted fields are cleared. Enabling it makes the server auto-reply to anyone who mails the account, also after the MCP session ends, until `to_date`, so `to_date` is required when enabling (in the future, at most 90 days ahead) and the subject and body must not contain private data. Clients should call `mail_vacation_get` first and enable only on the user's explicit request. Subject at most 998 characters, each body at most 64 KiB (requires `capabilities.vacation = true`) |
| `quota_get` | Storage quota usage and limits (`Quota/get`, RFC 9425) |
| `identity_list` | Sending identities: From addresses, reply-to, bcc, signatures |

Every tool takes an optional `account` argument; omit it for the default account.

### Prompts
| Prompt | Description |
|--------|-------------|
| `triage_inbox` | Summarize unread emails, flag what's important, suggest actions |
| `draft_reply` | Draft a contextual reply to a specific email (with tone control) |
| `search_and_summarize` | Search emails and present a structured summary |
| `train_spam_filter` | Review emails in a folder and train the spam filter |

### Resources
| URI | Description |
|-----|-------------|
| `mail://accounts` | List of configured accounts (name, username, default status) |
| `mail://{account}/folders` | Mailbox list with message and unread counts |
| `mail://{account}/messages/{id}` | Full email content by JMAP ID |

### Other features
- **Multi-account**: configure multiple Stalwart accounts with graceful degradation if one fails
- **Real-time notifications**: JMAP EventSource (SSE) pushes email changes to MCP client
- **Rate limiting**: per-tool token bucket (5-60 calls/min)
- **Audit logging**: structured tracing on every tool call
- **JWT auth**: required for all HTTP connections when a secret is configured; otherwise only loopback is allowed
- **Dual transport**: stdio (local) and Streamable HTTP (remote)

## Requirements

- [Rust](https://rustup.rs/) 1.89+
- A running [Stalwart Mail Server](https://stalw.art/) with JMAP enabled
- Stalwart v0.16+ for `spam_train`, Stalwart 1.1+ for the masked email tools (other tools are compatible with v0.15+)

## Versioning

Releases are numbered `<stalwart version>-<mcp revision>`. The first three numbers are the Stalwart Mail Server release the build was tested against; the number after the hyphen counts MCP-only releases on that Stalwart version. For example, `1.0.3-2` follows `1.0.3-1` on the same Stalwart, and `1.0.4-1` follows when Stalwart's API changes in 1.0.4. (Cargo requires three-part semver, hence `1.0.3-1` rather than `1.0.3.1`.) Releases before `1.0.3-1` (0.1.x, 0.2.0) keep their old numbers.

To pick a build for your server, take the newest tag whose first three numbers are at or below your Stalwart version.

| stalwart-mcp | Stalwart |
|--------------|----------|
| `1.0.3-1`    | 1.0.3    |
| `1.1.1-1`    | 1.1.1    |
| `1.1.1-2`    | 1.1.1    |

Test coverage for `1.0.3-1`: the HTTP transport, auth and the Sent/Drafts mailbox lookup were tested against a live Stalwart 1.0.3.

Test coverage for `1.1.1-1`, run live against Stalwart 1.1.1 (`tests/integration_mail.rs` and `tests/integration_account.rs`): connect and session capabilities; mailbox listing and role lookup; recent listing, search, full message, raw blob and Message-ID reads; the draft lifecycle (create, search, read/unread, move to Trash, permanent delete); masked email list, create, disable and destroy; vacation response get, set (disabled only) and restore; `Quota/get` (on an account without a disk quota, so an empty list) and `Identity/get`; `mail_send` (`Email/set` plus `EmailSubmission/set`, one real message, with the fixes from `1.1.1-2`).

Test coverage for `1.1.1-2`: every tool except `spam_train` (`SpamTrainingSample/set`) has now been run live against Stalwart 1.1.1, including `mail_send` and a draft whose From is the identity's address. Paths not exercised live: an enabled vacation response and the masked address quota error.

## Installation

```bash
git clone https://github.com/webpatser/stalwart-mcp.git
cd stalwart-mcp
cargo install --locked --path .
```

## Configuration

Create `~/.config/stalwart-mcp/config.toml`:

```toml
[[accounts]]
name = "personal"
url = "https://mail.example.com"
username = "user@example.com"
# password_env = "STALWART_PASSWORD"  # default

[[accounts]]
name = "work"
url = "https://mail.example.com"
username = "work@example.com"
password_env = "STALWART_PASSWORD_WORK"

# Optional: use first account if omitted
# default_account = "personal"

[capabilities]
# Allow sending emails (default: false)
# send = true
# Allow spam training via JMAP SpamTrainingSample/set (default: false, requires Stalwart v0.16+)
# spam_training = true
# Allow creating and disabling masked email addresses (default: false, requires Stalwart 1.1+).
# Listing them is always allowed.
# masked_email = true
# Allow changing the vacation response (default: false). An enabled response makes
# the server auto-reply to every sender, also after the session ends, until its
# to_date (required, at most 90 days ahead). Reading it is always allowed.
# vacation = true

[notifications]
# Real-time email notifications via JMAP EventSource (default: true)
# enabled = true
# ping_interval = 30

[server]
# For HTTP behind a reverse proxy, allow its public hostname (optionally with port).
# Omit or leave empty to retain rmcp's localhost/127.0.0.1/::1 defaults.
# Setting this requires auth.secret; HTTP mode refuses to start without it.
# allowed_hosts = ["mcp.example.com"]

[auth]
# JWT secret for HTTP mode (auto-generated on first `token create`)
# secret = "your-secret-here"
```

Set your password(s) as environment variables:

```bash
export STALWART_PASSWORD="your-password"
export STALWART_PASSWORD_WORK="work-password"
```

## Connecting to AI assistants

### Claude Code (CLI)

Add to your project's `.mcp.json`:

```json
{
  "mcpServers": {
    "stalwart": {
      "type": "stdio",
      "command": "/path/to/stalwart-mcp",
      "args": ["serve"],
      "env": {
        "STALWART_PASSWORD": "<your-password>"
      }
    }
  }
}
```

### Claude Desktop

Add to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS):

```json
{
  "mcpServers": {
    "stalwart": {
      "command": "stalwart-mcp",
      "args": ["serve"],
      "env": {
        "STALWART_PASSWORD": "<your-password>"
      }
    }
  }
}
```

### Cursor

Add to `.cursor/mcp.json` in your project:

```json
{
  "mcpServers": {
    "stalwart": {
      "command": "stalwart-mcp",
      "args": ["serve"],
      "env": {
        "STALWART_PASSWORD": "<your-password>"
      }
    }
  }
}
```

### Remote mode (HTTP with JWT)

For remote deployment, run as an HTTP server:

```bash
stalwart-mcp serve --bind 127.0.0.1:3000
```

Generate a JWT token for remote access:

```bash
stalwart-mcp token create --account "*" --scopes "mail:read,mail:modify" --expires 365
```

Scopes and `--account` are enforced on every tool call and resource read. A token restricted to one account (`--account work`) may only name that account; a call without `account` is run against it, and the `mail://accounts` resource lists only that account. Accepted scopes are `mail:read`, `mail:modify`, `mail:send` and `*` (all); `token create` rejects anything else. Scopes do not imply each other: a token that drafts and reads needs `mail:read,mail:modify`. Reading resources needs `mail:read`. The default scope is `mail:read`, so a token created without `--scopes` is read-only.

| Scope | Tools |
|-------|-------|
| `mail:read` | `mail_list_folders`, `mail_list_recent`, `mail_search`, `mail_get`, `mail_masked_list`, `mail_vacation_get`, `quota_get`, `identity_list` |
| `mail:modify` | `mail_flag`, `mail_move`, `mail_draft`, `mail_bulk_read`, `mail_bulk_junk`, `mail_bulk_delete`, `mail_masked_create`, `mail_masked_disable`, `spam_train` |
| `mail:send` | `mail_send`, `mail_vacation_set` (an enabled vacation response makes the server send auto-replies) |

Capability flags in the config still apply on top of scopes. Over stdio and for loopback HTTP requests without `auth.secret` there is no token, so everything is allowed.

Then configure your client to connect via HTTP:

```json
{
  "mcpServers": {
    "stalwart": {
      "url": "https://your-server:3000/mcp",
      "authentication": {
        "type": "bearer",
        "token": "<jwt-token-from-above>"
      }
    }
  }
}
```

**Note:** With `auth.secret` configured, every HTTP request requires a valid JWT, including loopback requests from a reverse proxy. Without a secret, every request arriving from loopback is trusted and all others are rejected. A reverse proxy on the same host makes every request arrive from loopback, so without a secret it exposes the server unauthenticated. HTTP mode refuses to start when `server.allowed_hosts` is set and `auth.secret` is empty, but it cannot detect a proxy: with `allowed_hosts` unset, a proxy that forwards a loopback Host (nginx `proxy_pass http://127.0.0.1:3000` does by default) still gets through. Always set `auth.secret` when the server sits behind a reverse proxy or is reachable by anything other than local clients. TLS should be handled by a reverse proxy (nginx, caddy) or Stalwart's own TLS.

## Example interactions

Once connected, ask your AI assistant:

- "List my mail folders"
- "Show me today's unread emails"
- "Search for emails about the contract renewal"
- "Mark that email as read"
- "Move the newsletter to Archive"
- "Draft a reply to the latest email from support"

## CLI reference

```
stalwart-mcp serve [OPTIONS]        Start the MCP server
    --stdio                         Use stdio transport (default)
    --bind <ADDR>                   HTTP transport (e.g. 127.0.0.1:3000)

stalwart-mcp token create           Generate a JWT token
    --account <NAME>                Account name or "*" for all (default: *)
    --scopes <SCOPES>               Comma-separated: mail:read,mail:modify,mail:send or * (default: mail:read)
    --expires <DAYS>                Token expiry in days (default: 365)

Global options:
    -c, --config <PATH>             Path to config file
```

## Development

```bash
cargo build --locked                    # Build
cargo build --locked --release          # Release build
cargo test --locked                     # Run tests
cargo clippy --locked --all-targets     # Lint
cargo fmt                      # Format
```

### Integration tests

```bash
export STALWART_TEST_URL="https://mail.example.com"
export STALWART_TEST_USER="user@example.com"
export STALWART_PASSWORD="your-password"
cargo test --locked -- --ignored --test-threads=1
```

The account tests (`tests/integration_account.rs`) write to the account and restore it: they create, disable and destroy one masked address, and set a disabled vacation response before putting the prior one back. They skip the vacation write when an auto-reply is active.

The send test (`test_send_email` in `tests/integration_mail.rs`) sends one real plain-text message per run and is skipped unless `STALWART_TEST_SEND_TO` names the recipient; it checks that the copy lands in Sent without `$draft` and with the identity's address as From, then removes that copy. Keep the address in your environment, never in the repo:

```bash
export STALWART_TEST_SEND_TO="someone-who-agreed@example.com"
cargo test --locked --test integration_mail test_send_email -- --ignored --nocapture
```

## Architecture

```
AI Client (Claude/Cursor)
    | MCP (stdio or Streamable HTTP)
    v
stalwart-mcp
    | JMAP over HTTPS        | JMAP EventSource (SSE)
    v                        v
Stalwart Mail Server    (real-time notifications)
```

## Roadmap

- [ ] Calendar tools (JMAP JSCalendar)
- [ ] Contacts tools (JMAP JSContact)
- [x] MCP Prompts (triage_inbox, draft_reply, search_and_summarize)
- [x] MCP Resources (accounts, folders, messages)
- [ ] Docker image
- [ ] Publish to crates.io

## License

AGPL-3.0. See [LICENSE](LICENSE).
