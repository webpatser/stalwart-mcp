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
| `mail_search` | Search by full-text, sender, recipient, subject, date, attachments. Optional `snippets: true` adds highlighted `subject` and `preview` excerpts per result (`SearchSnippet/get`; the server marks matches with `<mark>` tags, returned as is) |
| `mail_get` | Full message content with attachment metadata |
| `mail_get_thread` | The conversation of a message (`Thread/get`), oldest first in the server's thread order, as message summaries. Default 20, at most 50 messages; a longer thread returns the most recent ones and an `omitted` count |

### Write
| Tool | Description |
|------|-------------|
| `mail_flag` | Mark as read/unread/flagged/unflagged/junk/notjunk (junk auto-moves to Junk folder) |
| `mail_move` | Move to folder (Archive, Trash, etc.) |
| `mail_bulk_junk` | Bulk mark emails as junk/notjunk in a single JMAP request |
| `mail_bulk_delete` | Delete multiple emails in a single JMAP request: moves them to Trash by default (fails if no Trash mailbox exists); `permanent: true` destroys them and requires `capabilities.delete` |
| `mail_bulk_read` | Bulk mark emails as read in a single JMAP request |
| `mail_draft` | Save draft in Drafts folder |
| `mail_send` | Send email (requires `capabilities.send = true` in config) |
| `spam_train` | Train Stalwart's Bayes classifier via JMAP `x:SpamTrainingSample/set` (requires Stalwart v0.16+ and `capabilities.spam_training = true`) |

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
| `sieve_list` | Sieve filter scripts: ID, name and which one is active (`SieveScript/get`, RFC 9661) |
| `sieve_get` | One Sieve script with its source, downloaded from its blob |
| `sieve_validate` | Compile a Sieve script on the server without storing it as a script; returns `valid` and the server's error. At most 64 KiB. The script is uploaded as a temporary blob that the server expires, which is why the tool is rate-limited although it needs only `mail:read` |
| `sieve_put` | Create a Sieve script or replace the source of one by `id`. A wrong script can discard or redirect incoming mail. The script is always validated first and refused if it does not compile; it is stored inactive unless `activate: true`. The name `vacation` is reserved for the vacation response, and the server-managed `vacation` script cannot be replaced by `id`. Replacing the active script changes live filtering and is refused unless `activate: true`; an unknown `id` is refused before anything is uploaded. Names are at most 128 bytes, not `.` or `..`, without `/` or control characters. At most 64 KiB (requires `capabilities.sieve = true`) |
| `contacts_search` | Search contacts by text (`ContactCard/query`, RFC 9610; the server matches whole words in name, email, organisation and other card fields), or list them when `query` is omitted. Returns only name, email addresses, organisations and address book names; nothing else is requested from the server. Default 20, at most 50 results. Needs `urn:ietf:params:jmap:contacts` in the session |

`contacts_search` was verified live against Stalwart 1.1.1: a live test creates one made-up card, finds it by text search, checks that name, email address, organisation and address book are extracted, then destroys it and asserts the card count is unchanged.

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
| `1.1.1-3`    | 1.1.1    |
| `1.1.1-4`    | 1.1.1    |

Test coverage for `1.0.3-1`: the HTTP transport, auth and the Sent/Drafts mailbox lookup were tested against a live Stalwart 1.0.3.

Test coverage for `1.1.1-1`, run live against Stalwart 1.1.1 (`tests/integration_mail.rs` and `tests/integration_account.rs`): connect and session capabilities; mailbox listing and role lookup; recent listing, search, full message, raw blob and Message-ID reads; the draft lifecycle (create, search, read/unread, both `mail_bulk_delete` modes: bulk move to Trash, then permanent delete); masked email list, create, disable and destroy; vacation response get, set (disabled only) and restore; `Quota/get` (on an account without a disk quota, so an empty list) and `Identity/get`; `mail_send` (`Email/set` plus `EmailSubmission/set`, one real message, with the fixes from `1.1.1-2`).

Test coverage for `1.1.1-2`: every tool except `spam_train` and `mail_bulk_junk` has now been run live against Stalwart 1.1.1, including `mail_send` and a draft whose From is the identity's address. Paths not exercised live: an enabled vacation response and the masked address quota error.

Test coverage for `1.1.1-4`, run live against Stalwart 1.1.1, once each: `mail_bulk_junk`'s JMAP path (`test_bulk_junk`) passed: a draft was moved into Junk with `$junk` and back to Drafts, the server stored one training sample per move, and the test destroyed both, the draft, and confirmed the sample count was back to its prior value. `spam_train` (`test_spam_training`) reached the server with the corrected `x:SpamTrainingSample/set` call, which Stalwart refused with `forbidden` ("You are not authorized to create objects of this type") for a plain user account; nothing was created and the draft was removed. A successful `spam_train` has not been run live: it needs an account with the permission to create spam training samples, and the clearer error for this refusal was added after the run and is covered by unit tests only. Sieve activation (`sieve_put` with `activate: true`) has never been run live: the live tests store scripts inactive only and never activate one.

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
# Allow spam training via JMAP x:SpamTrainingSample/set (default: false, requires Stalwart v0.16+)
# spam_training = true
# Allow creating and disabling masked email addresses (default: false, requires Stalwart 1.1+).
# Listing them is always allowed.
# masked_email = true
# Allow changing the vacation response (default: false). An enabled response makes
# the server auto-reply to every sender, also after the session ends, until its
# to_date (required, at most 90 days ahead). Reading it is always allowed.
# vacation = true
# Allow mail_bulk_delete with permanent = true, which destroys emails beyond
# recovery (default: false). Moving them to Trash, the default, is always allowed.
# delete = true
# Allow sieve_put to create or replace Sieve filter scripts (default: false). A
# wrong script can discard or redirect incoming mail. Listing, reading and
# validating scripts is always allowed.
# sieve = true

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

## Connecting a client

This is the one place for client setup. Stdio is the default for local use; HTTP is for remote or shared use.

### Prerequisites

- The binary is installed (`cargo install --path . --locked`, see [Installation](#installation)), by default at `~/.cargo/bin/stalwart-mcp`.
- A config file whose accounts read the password from an environment variable (`password_env`, see [Configuration](#configuration)).

### Recommended local layout

Keep the password out of every client config file. The config holds no password, and a small env file exports only the password variable:

```
~/.config/stalwart-mcp/config.toml     mode 0600, accounts with password_env
~/.config/stalwart-mcp/personal.env    mode 0600, exports only the password variable
```

```bash
mkdir -p ~/.config/stalwart-mcp
cat > ~/.config/stalwart-mcp/personal.env <<'ENV'
STALWART_PASSWORD='your-password'
ENV
chmod 600 ~/.config/stalwart-mcp/personal.env ~/.config/stalwart-mcp/config.toml
```

```toml
[[accounts]]
name = "personal"
url = "https://mail.example.org"
username = "you@example.org"
# password_env defaults to STALWART_PASSWORD
```

The clients below start the server through `/bin/sh -c`, which sources the env file (`set -a` exports every variable it defines), then `exec`s the binary:

```sh
set -a; . "$HOME/.config/stalwart-mcp/personal.env"; set +a; exec "$HOME/.cargo/bin/stalwart-mcp" --config "$HOME/.config/stalwart-mcp/config.toml" serve --stdio
```

### Claude Code

**Project scope**: add to `.mcp.json` in the project root.

```json
{
  "mcpServers": {
    "stalwart": {
      "type": "stdio",
      "command": "/bin/sh",
      "args": [
        "-c",
        "set -a; . \"$HOME/.config/stalwart-mcp/personal.env\"; set +a; exec \"$HOME/.cargo/bin/stalwart-mcp\" --config \"$HOME/.config/stalwart-mcp/config.toml\" serve --stdio"
      ]
    }
  }
}
```

- Keep `.mcp.json` git-ignored if it is machine-specific (this repository's `.gitignore` already does).
- Claude Code asks once to approve a project server.
- Start a new session afterwards; running sessions do not pick up the change.

**User scope** (all projects), the same wrapper through `claude mcp add`:

```bash
claude mcp add --scope user stalwart -- /bin/sh -c 'set -a; . "$HOME/.config/stalwart-mcp/personal.env"; set +a; exec "$HOME/.cargo/bin/stalwart-mcp" --config "$HOME/.config/stalwart-mcp/config.toml" serve --stdio'
```

**Check**: run `claude mcp list` in a shell, or `/mcp` inside a session. `stalwart` should show as connected.

### Claude Desktop

Open Settings, Developer, Edit Config, or edit the file directly:

| OS | File |
|----|------|
| macOS | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Windows | `%APPDATA%\Claude\claude_desktop_config.json` |

```json
{
  "mcpServers": {
    "stalwart": {
      "command": "/bin/sh",
      "args": [
        "-c",
        "set -a; . \"$HOME/.config/stalwart-mcp/personal.env\"; set +a; exec \"$HOME/.cargo/bin/stalwart-mcp\" --config \"$HOME/.config/stalwart-mcp/config.toml\" serve --stdio"
      ]
    }
  }
}
```

Desktop does not expand `$HOME` in `command`, so the wrapper script does it. Restart Desktop afterwards.

The `/bin/sh` wrapper is for macOS and Linux. On Windows, point `command` at the binary, put `--config <path>`, `serve` and `--stdio` in `args`, and carry the password variable in the entry's `env` block (for example `"env": { "STALWART_PASSWORD": "your-password" }`); that file then contains the password, so keep it private.

### Other MCP clients (stdio)

- Command: `stalwart-mcp` (or its full path), or the `/bin/sh -c` wrapper above.
- Args: `--config <path> serve --stdio` (`--config` defaults to `~/.config/stalwart-mcp/config.toml`).
- Environment: the variable named by `password_env` (default `STALWART_PASSWORD`) must be set for the process the client launches.

### Remote or shared use over HTTP

1. Set `auth.secret` in the config (`[auth]`, `secret = "..."`). If none is set, the first `token create` generates one and prints the `[auth]` block to add.
2. Start the server:

   ```bash
   stalwart-mcp serve --bind 127.0.0.1:3000
   ```

3. Create a token with only the scopes the client needs:

   ```bash
   stalwart-mcp token create --account "*" --scopes "mail:read,mail:modify" --expires 365
   ```

4. Connect with a streamable HTTP client at `https://mcp.example.org/mcp` sending `Authorization: Bearer <token>`. In Claude Code:

   ```bash
   claude mcp add --transport http stalwart https://mcp.example.org/mcp --header "Authorization: Bearer <token>"
   ```

Scopes and `--account` are enforced on every tool call and resource read. A token restricted to one account (`--account work`) may only name that account; a call without `account` is run against it, and the `mail://accounts` resource lists only that account. Accepted scopes are `mail:read`, `mail:modify`, `mail:send` and `*` (all); `token create` rejects anything else. Scopes do not imply each other: a token that drafts and reads needs `mail:read,mail:modify`. Reading resources needs `mail:read`. The default scope is `mail:read`, so a token created without `--scopes` is read-only: it cannot modify or send.

| Scope | Tools |
|-------|-------|
| `mail:read` | `mail_list_folders`, `mail_list_recent`, `mail_search`, `mail_get`, `mail_get_thread`, `mail_masked_list`, `mail_vacation_get`, `quota_get`, `identity_list`, `sieve_list`, `sieve_get`, `sieve_validate`, `contacts_search` |
| `mail:modify` | `mail_flag`, `mail_move`, `mail_draft`, `mail_bulk_read`, `mail_bulk_junk`, `mail_bulk_delete`, `mail_masked_create`, `mail_masked_disable`, `spam_train` |
| `mail:send` | `mail_send`, `mail_vacation_set` (an enabled vacation response makes the server send auto-replies), `sieve_put` (a script can redirect mail) |

Capability flags in the config still apply on top of scopes. Over stdio and for loopback HTTP requests without `auth.secret` there is no token, so everything is allowed.

**Note:** With `auth.secret` configured, every HTTP request requires a valid JWT, including loopback requests from a reverse proxy. Without a secret, a request arriving from loopback is trusted and all others are rejected. A reverse proxy on the same host makes every request arrive from loopback, so without a secret, a loopback request that carries any of `Forwarded`, `X-Forwarded-For`, `X-Real-IP`, `X-Forwarded-Host`, `X-Forwarded-Proto`, `X-Forwarded-Port`, `Via`, `CF-Connecting-IP`, `True-Client-IP` or `X-Client-IP` (any value, any casing) is rejected with 401 and a warning naming `auth.secret`. This closes the common case of an nginx, caddy or Cloudflare setup that adds one of those headers. It cannot detect a proxy that adds none of them: such a proxy (nginx `proxy_pass http://127.0.0.1:3000` without `proxy_set_header`, which also forwards a loopback Host by default) still gets through unauthenticated. HTTP mode also refuses to start when `server.allowed_hosts` is set and `auth.secret` is empty. Always set `auth.secret` when the server sits behind a reverse proxy or is reachable by anything other than local clients. TLS should be handled by a reverse proxy (nginx, caddy) or Stalwart's own TLS.

### What each client can do

Every client gets the same tools, limited by the token scopes over HTTP. The capability flags in the config (`send`, `delete`, `sieve`, `vacation`, `masked_email`, `spam_training`) are off unless you enable them, see [Configuration](#configuration) and the tool table under [Tools](#tools).

### Troubleshooting

- Tools do not appear: restart the client (Claude Code needs a new session), approve the project server when asked, and run `claude mcp list`.
- Authentication failed or `Environment variable 'STALWART_PASSWORD' not set`: the password variable is not set in the environment the client launches; check the env file path in the wrapper.
- 401 over HTTP: the token is missing or expired, or a proxy forwarded headers while no `auth.secret` is set.
- `Forbidden: this token lacks the '<scope>' scope`: create a new token with that scope.
- A tool says it is disabled (for example `Sending emails is disabled`): enable its flag under `[capabilities]` and restart the server.
- Logs: the server writes tracing output to stderr only (stdout carries the protocol); the level comes from `RUST_LOG`, default `info`. The client decides where stderr goes.

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

stalwart-mcp account add            Add an account (checks the credentials first)
    --name <NAME>                   Account name: letters, digits, - and _, at most 64
    --url <URL>                     JMAP server URL, e.g. https://mail.example.com
    --username <USER>               Login username
    --default                       Make it the default account (the first account always is)
    --password-source <SOURCE>      env or command (1password and keychain: not available yet)
    --password-env <VAR>            Environment variable holding the password (source env)
    --password-command <ARG>        Program and arguments that print the password, one flag
                                    per argument (source command); the program is stored
                                    as an absolute path
    --no-verify                     Write without checking the credentials
    -y, --yes                       Do not ask for confirmation

stalwart-mcp account list           Name, URL, username, password source, default marker
    --json                          Stable machine-readable output

stalwart-mcp account edit <NAME>    Change only the given values; same flags as add, plus
    --rename <NAME>                 New name (the default account follows a rename)

stalwart-mcp account remove <NAME>  Remove an account; a removed default moves to the
    -y, --yes                       first remaining account

stalwart-mcp account test [NAME]    Connect one or all accounts, print ok or the error;
                                    exits non-zero when any account fails

Global options:
    -c, --config <PATH>             Path to config file
```

The `account` commands need no existing config: `account add` creates the file (mode 0600, directory 0700) and keeps comments and unknown keys when it edits one. A value missing from the flags is asked for when stdin is a terminal; otherwise the error names the flag, and confirmations need `--yes`. `add` and `edit` check the credentials against the server before anything is written (when the URL, username or password source changes), then write the config and read the password from the stored source once more as a final check. Passwords are never shown, and `list` shows only the program name of a password command, not its arguments.

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

`test_spam_training` and `test_bulk_junk` only run with `STALWART_TEST_SPAM_TRAIN=1`, because they feed the account's spam classifier. Each creates its own draft: the first trains it once through `x:SpamTrainingSample/set`, the second moves it into Junk and back through the `mail_bulk_junk` path (Stalwart stores a training sample on each of those moves). Both then destroy exactly the samples they caused and the draft, and check the sample count is back. Destroying a sample does not undo training the classifier has already done from it.

The send test (`test_send_email` in `tests/integration_mail.rs`) sends one real plain-text message per run and is skipped unless `STALWART_TEST_SEND_TO` names the recipient; it checks that the copy lands in Sent without `$draft` and with the identity's address as From, then removes that copy. Keep the address in your environment, never in the repo:

```bash
export STALWART_TEST_SEND_TO="someone-who-agreed@example.com"
cargo test --locked --test integration_mail test_send_email -- --ignored --nocapture
```

### End-to-end script

`scripts/e2e.py` drives an installed `stalwart-mcp` binary as an MCP client, over stdio and streamable HTTP, against a live Stalwart. It needs only the Python 3 standard library.

```bash
cargo install --path . --locked
export STALWART_TEST_URL="https://mail.example.com"
export STALWART_TEST_USER="user@example.com"
export STALWART_PASSWORD="your-password"
python3 -I scripts/e2e.py
```

During the run a secret-less instance listens on a loopback port with access to the test mailbox, so run it only on a single-user machine.

It covers the initialize handshake and version, tools, prompts and resources; every read tool; the draft lifecycle (flags, move, bulk read, both `mail_bulk_delete` modes); masked email create, disable and destroy; a disabled vacation response with restore; capability gates; and over HTTP: JWT required, tampered token and foreign Host refused, a read-only token refused on `mail_draft`, an account-restricted token refused another account, a forwarded request refused without a secret, and a body over 2 MB answered with 413.

It works on what it creates and removes it: its draft, its masked address, the disabled vacation response (restored to the prior one) and the inactive Sieve script that write leaves behind, then checks that nothing is left and prints a `CLEANUP` line per item. It skips the vacation write when an auto-reply is active and never trains the spam filter. Config files and logs go to a private temporary directory that is deleted at the end. Output never contains the credentials, and email local parts are redacted.

By default it sends no mail. `--send` sends one plain-text message to `STALWART_TEST_SEND_TO` and leaves its Sent copy in place. Other options: `--bin` (binary path, default `~/.cargo/bin/stalwart-mcp`), `--port` (HTTP test port, default 38766), `--keep-logs`.

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
