//! Command-line interface: the clap definitions shared by the binary and the
//! tests, plus the seams the `account` subcommands use for terminal input
//! ([`Prompter`]) and for checking credentials against the server
//! ([`Verifier`]).

pub mod account;

use crate::config::AccountConfig;
use crate::error::AppError;
use crate::jmap::JmapClient;
use crate::secret::Secret;
use clap::{Parser, Subcommand};
use std::io::{BufRead, IsTerminal, Write};
use std::path::PathBuf;
use thiserror::Error;

pub use account::AccountCommand;

#[derive(Debug, Parser)]
#[command(
    name = "stalwart-mcp",
    version,
    about = "MCP server for Stalwart Mail Server"
)]
pub struct Cli {
    /// Path to config file (default: ~/.config/stalwart-mcp/config.toml)
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Start the MCP server
    Serve {
        /// Use stdio transport (for Claude Desktop / Cursor)
        #[arg(long, default_value_t = true, conflicts_with = "bind")]
        stdio: bool,

        /// Bind address for HTTP transport (e.g. 127.0.0.1:3000)
        #[arg(long)]
        bind: Option<String>,
    },

    /// Manage JWT tokens for HTTP authentication
    Token {
        #[command(subcommand)]
        action: TokenAction,
    },

    /// Add, list, edit, remove and test mail accounts in the config file
    Account {
        #[command(subcommand)]
        action: AccountCommand,
    },
}

#[derive(Debug, Subcommand)]
pub enum TokenAction {
    /// Create a new JWT token
    Create {
        /// Account name to authorize (or "*" for all accounts)
        #[arg(long, default_value = "*")]
        account: String,

        /// Comma-separated scopes: mail:read, mail:modify, mail:send, or * for all
        #[arg(long, default_value = "mail:read")]
        scopes: String,

        /// Token expiry in days
        #[arg(long, default_value = "365")]
        expires: u64,
    },
}

/// Errors of the `account` subcommands. No variant ever carries a password.
#[derive(Debug, Error)]
pub enum CliError {
    /// Wrong or missing input; the message names the flag.
    #[error("{0}")]
    Usage(String),
    /// A flag or source that a later version fills in.
    #[error("{0} is not available yet in this version")]
    NotAvailable(String),
    /// A credential check or password source failed.
    #[error("{0}")]
    Failed(String),
    /// A confirmation was declined.
    #[error("aborted; nothing was changed")]
    Aborted,
    #[error(transparent)]
    App(#[from] AppError),
    #[error("cannot write output: {0}")]
    Output(#[from] std::io::Error),
}

/// Terminal input for missing values and confirmations. Tests script it.
pub trait Prompter {
    /// True when questions can be asked (stdin is a terminal).
    fn interactive(&self) -> bool;
    /// Ask for a visible value; returns the raw answer (may be empty).
    fn ask(&mut self, question: &str, default: Option<&str>) -> Result<String, CliError>;
    /// Ask for a secret without echoing it.
    fn ask_secret(&mut self, question: &str) -> Result<Secret, CliError>;
    /// Read the password from stdin (`--password-stdin`).
    fn read_password_stdin(&mut self) -> Result<Secret, CliError>;
    /// Ask a yes/no question; the default is no.
    fn confirm(&mut self, question: &str) -> Result<bool, CliError>;
}

/// [`Prompter`] on the real terminal: questions on stderr, answers from
/// stdin, secrets through `rpassword` (no echo).
#[derive(Debug)]
pub struct TerminalPrompter {
    interactive: bool,
}

impl TerminalPrompter {
    pub fn new() -> Self {
        Self {
            interactive: std::io::stdin().is_terminal(),
        }
    }
}

impl Default for TerminalPrompter {
    fn default() -> Self {
        Self::new()
    }
}

fn input_error(e: std::io::Error) -> CliError {
    CliError::Usage(format!("cannot read from the terminal: {e}"))
}

impl Prompter for TerminalPrompter {
    fn interactive(&self) -> bool {
        self.interactive
    }

    fn ask(&mut self, question: &str, default: Option<&str>) -> Result<String, CliError> {
        let mut stderr = std::io::stderr();
        let written = match default {
            Some(d) => write!(stderr, "{question} [{d}]: "),
            None => write!(stderr, "{question}: "),
        };
        written.and_then(|()| stderr.flush()).map_err(input_error)?;
        let mut line = String::new();
        let read = std::io::stdin()
            .lock()
            .read_line(&mut line)
            .map_err(input_error)?;
        if read == 0 {
            return Err(CliError::Usage("no answer (end of input)".into()));
        }
        Ok(line.trim_end_matches(['\r', '\n']).to_string())
    }

    fn ask_secret(&mut self, question: &str) -> Result<Secret, CliError> {
        rpassword::prompt_password(format!("{question}: "))
            .map(Secret::new)
            .map_err(input_error)
    }

    fn read_password_stdin(&mut self) -> Result<Secret, CliError> {
        use std::io::Read;
        // One byte over the limit (plus a line break) so an oversized
        // password is refused rather than cut.
        let limit = crate::secret::MAX_PASSWORD_OUTPUT as u64 + 3;
        let mut bytes = Vec::new();
        std::io::stdin()
            .lock()
            .take(limit)
            .read_to_end(&mut bytes)
            .map_err(input_error)?;
        crate::secret_store::password_from_stdin(bytes).map_err(|e| CliError::Usage(e.to_string()))
    }

    fn confirm(&mut self, question: &str) -> Result<bool, CliError> {
        let answer = self.ask(&format!("{question} [y/N]"), None)?;
        Ok(matches!(
            answer.trim().to_ascii_lowercase().as_str(),
            "y" | "yes"
        ))
    }
}

/// Checks credentials against the server. Tests use a fake, so they need no
/// network.
pub trait Verifier {
    /// Succeeds when `password` logs in to `account` (url, username).
    fn verify(
        &self,
        account: &AccountConfig,
        password: &Secret,
    ) -> impl Future<Output = Result<(), AppError>>;
}

/// [`Verifier`] that fetches the JMAP session with the given password.
#[derive(Debug, Default, Clone, Copy)]
pub struct JmapVerifier;

impl Verifier for JmapVerifier {
    async fn verify(&self, account: &AccountConfig, password: &Secret) -> Result<(), AppError> {
        JmapClient::connect_with_password(account, password)
            .await
            .map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use account::SourceKind;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("stalwart-mcp").chain(args.iter().copied()))
    }

    fn account(args: &[&str]) -> AccountCommand {
        let mut all = vec!["account"];
        all.extend_from_slice(args);
        match parse(&all).expect("parses").command {
            Commands::Account { action } => action,
            other => panic!("not an account command: {other:?}"),
        }
    }

    #[test]
    fn serve_and_token_parse_as_before() {
        let cli = parse(&["serve"]).expect("serve");
        assert!(matches!(
            cli.command,
            Commands::Serve {
                stdio: true,
                bind: None
            }
        ));
        let cli = parse(&["serve", "--bind", "127.0.0.1:3000", "-c", "/x.toml"]).expect("bind");
        assert_eq!(cli.config, Some(PathBuf::from("/x.toml")));
        assert!(
            matches!(cli.command, Commands::Serve { bind: Some(b), .. } if b == "127.0.0.1:3000")
        );
        assert!(parse(&["serve", "--stdio", "--bind", "127.0.0.1:3000"]).is_err());

        let cli = parse(&["token", "create"]).expect("token");
        let Commands::Token {
            action:
                TokenAction::Create {
                    account,
                    scopes,
                    expires,
                },
        } = cli.command
        else {
            panic!("token")
        };
        assert_eq!(
            (account.as_str(), scopes.as_str(), expires),
            ("*", "mail:read", 365)
        );
        let cli = parse(&[
            "token",
            "create",
            "--account",
            "work",
            "--scopes",
            "*",
            "--expires",
            "7",
        ])
        .expect("token flags");
        assert!(matches!(
            cli.command,
            Commands::Token {
                action: TokenAction::Create { expires: 7, .. }
            }
        ));
    }

    #[test]
    fn account_add_takes_every_flag() {
        let AccountCommand::Add(args) = account(&[
            "add",
            "--name",
            "work",
            "--url",
            "https://mail.example.com",
            "--username",
            "u@example.com",
            "--default",
            "--password-source",
            "command",
            "--password-command",
            "/usr/bin/security",
            "--password-command",
            "-w",
            "--no-verify",
            "--yes",
        ]) else {
            panic!("add")
        };
        assert_eq!(args.name.as_deref(), Some("work"));
        assert_eq!(args.url.as_deref(), Some("https://mail.example.com"));
        assert_eq!(args.username.as_deref(), Some("u@example.com"));
        assert!(args.default && args.no_verify && args.yes);
        assert_eq!(args.source.password_source, Some(SourceKind::Command));
        assert_eq!(args.source.password_command, ["/usr/bin/security", "-w"]);

        for source in ["1password", "keychain", "env", "command"] {
            let AccountCommand::Add(args) = account(&["add", "--password-source", source]) else {
                panic!("add")
            };
            assert!(args.source.password_source.is_some());
        }
        let AccountCommand::Add(args) = account(&[
            "add",
            "--op-reference",
            "op://v/i/password",
            "--op-vault",
            "Private",
        ]) else {
            panic!("add")
        };
        assert_eq!(args.source.op_vault.as_deref(), Some("Private"));
        let AccountCommand::Add(args) = account(&["add", "--password-stdin"]) else {
            panic!("add")
        };
        assert!(args.source.password_stdin);
    }

    #[test]
    fn account_flag_conflicts_are_rejected() {
        for args in [
            &[
                "account",
                "add",
                "--password-env",
                "X",
                "--password-command",
                "/bin/echo",
            ][..],
            &[
                "account",
                "add",
                "--password-stdin",
                "--password-command",
                "/bin/echo",
            ],
            &[
                "account",
                "add",
                "--op-reference",
                "op://a/b/c",
                "--password-command",
                "/x",
            ],
            &[
                "account",
                "add",
                "--op-reference",
                "op://a/b/c",
                "--password-env",
                "X",
            ],
            &[
                "account",
                "add",
                "--op-reference",
                "op://a/b/c",
                "--password-stdin",
            ],
            &["account", "add", "--password-source", "bogus"],
            &["account", "edit"],
            &["account", "remove"],
            &["account", "list", "extra"],
        ] {
            assert!(parse(args).is_err(), "{args:?} should be rejected");
        }
    }

    #[test]
    fn account_list_edit_remove_test_parse() {
        assert!(matches!(
            account(&["list"]),
            AccountCommand::List { json: false }
        ));
        assert!(matches!(
            account(&["list", "--json"]),
            AccountCommand::List { json: true }
        ));

        let AccountCommand::Edit(args) = account(&[
            "edit",
            "work",
            "--rename",
            "main",
            "--url",
            "https://b.example.com",
            "--username",
            "b@example.com",
            "--default",
            "--password-env",
            "B_PASSWORD",
            "--no-verify",
            "--yes",
        ]) else {
            panic!("edit")
        };
        assert_eq!(args.name, "work");
        assert_eq!(args.rename.as_deref(), Some("main"));
        assert_eq!(args.source.password_env.as_deref(), Some("B_PASSWORD"));
        assert!(args.default && args.no_verify && args.yes);

        let AccountCommand::Remove(args) = account(&["remove", "work", "--yes", "--delete-secret"])
        else {
            panic!("remove")
        };
        assert_eq!(args.name, "work");
        assert!(args.yes && args.delete_secret);

        assert!(matches!(
            account(&["test"]),
            AccountCommand::Test { name: None }
        ));
        assert!(matches!(
            account(&["test", "work"]),
            AccountCommand::Test { name: Some(n) } if n == "work"
        ));

        // The global --config works after the account subcommand too.
        let cli = parse(&["account", "list", "--config", "/tmp/c.toml"]).expect("global");
        assert_eq!(cli.config, Some(PathBuf::from("/tmp/c.toml")));
    }
}
