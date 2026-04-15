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
| `spam_train` | Train Stalwart's Bayes classifier with emails as spam/ham (requires `capabilities.spam_training = true`) |

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
- **JWT auth**: required for remote (non-localhost) HTTP connections
- **Dual transport**: stdio (local) and Streamable HTTP (remote)

## Requirements

- [Rust](https://rustup.rs/) 1.85+
- A running [Stalwart Mail Server](https://stalw.art/) with JMAP enabled

## Installation

```bash
git clone https://github.com/webpatser/stalwart-mcp.git
cd stalwart-mcp
cargo install --path .
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
# Allow spam training via admin API (default: false)
# spam_training = true

[admin_api]
# Admin username for Stalwart admin API (default: "admin")
# username = "admin"
# Env var for admin password (default: "STALWART_ADMIN_PASSWORD")
# password_env = "STALWART_ADMIN_PASSWORD"

[notifications]
# Real-time email notifications via JMAP EventSource (default: true)
# enabled = true
# ping_interval = 30

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

**Note:** Local (127.0.0.1) requests skip JWT auth. Remote requests always require a valid token. TLS should be handled by a reverse proxy (nginx, caddy) or Stalwart's own TLS.

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
    --scopes <SCOPES>               Comma-separated: mail:read,mail:modify,mail:send
    --expires <DAYS>                Token expiry in days (default: 365)

Global options:
    -c, --config <PATH>             Path to config file
```

## Development

```bash
cargo build                    # Build
cargo build --release          # Release build
cargo test                     # Run tests
cargo clippy --all-targets     # Lint
cargo fmt                      # Format
```

### Integration tests

```bash
export STALWART_TEST_URL="https://mail.example.com"
export STALWART_TEST_USER="user@example.com"
export STALWART_PASSWORD="your-password"
cargo test -- --ignored
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
