//! `stalwart-mcp account add | list | edit | remove | test`: create and
//! maintain the accounts in the config file.
//!
//! None of these needs an existing config. Values come from flags; a missing
//! value is asked for only when a terminal is available, otherwise the error
//! names the flag. Passwords stay in memory ([`Secret`]) and never reach
//! output, errors or the config file.
//!
//! Password sources: [`SourceKind`] is what the user picks, [`choose_source`]
//! turns flags and answers into a [`ChosenSource`], and
//! [`ChosenSource::password`] / [`ChosenSource::store`] are the one place
//! where a source yields the password to verify with, and the
//! [`PasswordSetting`] for the config plus an optional [`StoredSecret`] that a
//! later failure rolls back. The 1Password and Keychain programs come from
//! [`SecretStores`], which tests replace with fake scripts.
//!
//! Renaming an account whose source is its own Keychain item (service
//! `stalwart-mcp`, account = the old name) moves the item: the password is
//! stored under the new name, the config is written and checked, and only
//! then is the old item deleted. A failure before that point deletes the new
//! item again and leaves the old one untouched.

use super::{CliError, Prompter, Verifier};
use crate::config::{AccountConfig, AppConfig, DEFAULT_PASSWORD_ENV};
use crate::config_edit::{
    AccountEntry, AccountUpdate, ConfigDocument, DefaultAccountChange, PasswordSetting,
};
use crate::secret::{
    DEFAULT_COMMAND_TIMEOUT, Secret, program_permission_warnings, run_password_command,
};
use crate::secret_store::{
    CreatedItem, KEYCHAIN_SERVICE, Keychain, NewLogin, OnePassword, OpAccount, OpReference,
    SecretStores, StoreError, check_keychain_password, is_executable_file, matching_items,
};
use clap::{Args, Subcommand, ValueEnum};
use std::ffi::OsStr;
use std::fmt;
use std::io::Write;
use std::path::Path;

/// Longest account name accepted for new and renamed accounts.
const MAX_NAME_LEN: usize = 64;

#[derive(Debug, Subcommand)]
pub enum AccountCommand {
    /// Add an account; the credentials are checked before anything is written
    Add(AddArgs),
    /// List the configured accounts (never shows a password)
    List {
        /// Stable machine-readable output
        #[arg(long)]
        json: bool,
    },
    /// Change an account; only the given values change
    Edit(EditArgs),
    /// Remove an account
    Remove(RemoveArgs),
    /// Connect one or all accounts and print ok or the error per account
    Test {
        /// Account to test (default: all)
        name: Option<String>,
    },
}

/// Where an account's password comes from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum SourceKind {
    /// A 1Password item, read with `op read`
    #[value(name = "1password")]
    OnePassword,
    /// The macOS Keychain
    Keychain,
    /// An environment variable
    Env,
    /// Your own command that prints the password
    Command,
}

impl SourceKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::OnePassword => "1password",
            Self::Keychain => "keychain",
            Self::Env => "env",
            Self::Command => "command",
        }
    }
}

/// Password source flags shared by `add` and `edit`.
#[derive(Debug, Args, Default)]
pub struct SourceArgs {
    /// Password source (inferred from the other password flags when omitted)
    #[arg(long, value_enum)]
    pub password_source: Option<SourceKind>,

    /// Environment variable holding the password (source env)
    #[arg(
        long,
        value_name = "VAR",
        conflicts_with_all = ["password_command", "op_reference", "op_vault", "password_stdin"]
    )]
    pub password_env: Option<String>,

    /// Program and arguments that print the password, one flag per argument (source command)
    #[arg(
        long,
        value_name = "ARG",
        allow_hyphen_values = true,
        conflicts_with_all = ["op_reference", "op_vault", "password_stdin"]
    )]
    pub password_command: Vec<String>,

    /// Existing 1Password item field, op://vault/item/field (source 1password)
    #[arg(long, value_name = "op://...", conflicts_with = "password_stdin")]
    pub op_reference: Option<String>,

    /// 1Password vault for a new item (source 1password)
    #[arg(long, value_name = "VAULT")]
    pub op_vault: Option<String>,

    /// Read the password to store from stdin (sources 1password and keychain)
    #[arg(long)]
    pub password_stdin: bool,

    /// Overwrite an existing Keychain item (source keychain)
    #[arg(long)]
    pub force: bool,

    /// Keychain service name; only for tests and the live check
    #[arg(long, hide = true, value_name = "SERVICE")]
    pub keychain_service: Option<String>,
}

#[derive(Debug, Args)]
pub struct AddArgs {
    /// Account name (letters, digits, - and _, at most 64)
    #[arg(long)]
    pub name: Option<String>,

    /// JMAP server URL, e.g. https://mail.example.com
    #[arg(long)]
    pub url: Option<String>,

    /// Login username
    #[arg(long)]
    pub username: Option<String>,

    /// Make this the default account (the first account always is)
    #[arg(long)]
    pub default: bool,

    #[command(flatten)]
    pub source: SourceArgs,

    /// Do not check the credentials against the server
    #[arg(long)]
    pub no_verify: bool,

    /// Do not ask for confirmation
    #[arg(short, long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct EditArgs {
    /// Account to change
    pub name: String,

    /// New account name
    #[arg(long, value_name = "NAME")]
    pub rename: Option<String>,

    /// New JMAP server URL
    #[arg(long)]
    pub url: Option<String>,

    /// New login username
    #[arg(long)]
    pub username: Option<String>,

    /// Make this the default account
    #[arg(long)]
    pub default: bool,

    #[command(flatten)]
    pub source: SourceArgs,

    /// Do not check the credentials against the server
    #[arg(long)]
    pub no_verify: bool,

    /// Do not ask for confirmation
    #[arg(short, long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct RemoveArgs {
    /// Account to remove
    pub name: String,

    /// Do not ask for confirmation
    #[arg(short, long)]
    pub yes: bool,

    /// Also delete the stored Keychain item (never a 1Password item)
    #[arg(long)]
    pub delete_secret: bool,

    /// Keychain service name; only for tests and the live check
    #[arg(long, hide = true, value_name = "SERVICE")]
    pub keychain_service: Option<String>,
}

/// Run one `account` subcommand against the config at `path` with the
/// password stores of this system. Returns `Ok(false)` when `test` found a
/// failing account.
pub async fn run(
    command: AccountCommand,
    path: &Path,
    prompter: &mut impl Prompter,
    verifier: &impl Verifier,
    out: &mut impl Write,
) -> Result<bool, CliError> {
    run_with_stores(
        command,
        path,
        prompter,
        verifier,
        &SecretStores::system(),
        out,
    )
    .await
}

/// [`run`] with explicit password stores (tests pass fake programs).
pub async fn run_with_stores(
    command: AccountCommand,
    path: &Path,
    prompter: &mut impl Prompter,
    verifier: &impl Verifier,
    stores: &SecretStores,
    out: &mut impl Write,
) -> Result<bool, CliError> {
    match command {
        AccountCommand::Add(args) => {
            let stores = with_keychain_service(stores, args.source.keychain_service.as_deref())?;
            add(args, path, &stores, prompter, verifier, out).await?;
        }
        AccountCommand::List { json } => list(path, json, out)?,
        AccountCommand::Edit(args) => {
            let stores = with_keychain_service(stores, args.source.keychain_service.as_deref())?;
            edit(args, path, &stores, prompter, verifier, out).await?;
        }
        AccountCommand::Remove(args) => {
            let stores = with_keychain_service(stores, args.keychain_service.as_deref())?;
            remove(args, path, &stores, prompter, out).await?;
        }
        AccountCommand::Test { name } => return test(path, name.as_deref(), verifier, out).await,
    }
    Ok(true)
}

/// Apply the hidden `--keychain-service` override. Only `stalwart-mcp` and
/// `stalwart-mcp-<suffix>` are accepted, so the override cannot point the
/// CLI (or `--delete-secret`) at another program's Keychain items.
fn with_keychain_service(
    stores: &SecretStores,
    service: Option<&str>,
) -> Result<SecretStores, CliError> {
    let mut stores = stores.clone();
    let Some(service) = service else {
        return Ok(stores);
    };
    let valid = service == KEYCHAIN_SERVICE
        || service.strip_prefix("stalwart-mcp-").is_some_and(|suffix| {
            !suffix.is_empty()
                && suffix.len() <= MAX_NAME_LEN
                && suffix
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        });
    if !valid {
        return Err(CliError::Usage(format!(
            "invalid --keychain-service '{service}': use stalwart-mcp or stalwart-mcp-<suffix>"
        )));
    }
    stores.keychain = stores.keychain.map(|k| k.with_service(service));
    Ok(stores)
}

/// A password source picked for an account, before anything is stored.
#[derive(Debug)]
pub enum ChosenSource {
    /// Read from this environment variable.
    Env(String),
    /// Run this argv; the program is an absolute path.
    Command(Vec<String>),
    /// An existing 1Password item: the final `op read` argv (ids only).
    OnePasswordItem(Vec<String>),
    /// A new 1Password Login item, created from a typed password.
    OnePasswordNew {
        op: OnePassword,
        /// The `--account` id.
        account: String,
        /// The vault given by the user (name or id).
        vault: String,
        password: Secret,
    },
    /// A Keychain item under the account name, from a typed password.
    Keychain {
        keychain: Keychain,
        password: Secret,
        /// Overwrite an existing item (`--force`).
        force: bool,
    },
}

/// A secret this run wrote into a store (1Password, Keychain), kept so a later
/// failure can undo exactly that. The env and command sources store nothing,
/// and neither does a Keychain item that existed before (`--force`): that one
/// was overwritten, not created.
#[derive(Debug)]
pub enum StoredSecret {
    OnePassword {
        op: OnePassword,
        account: String,
        item: CreatedItem,
    },
    Keychain {
        keychain: Keychain,
        account: String,
    },
}

/// A rollback that did not succeed: the item to remove by hand and why.
#[derive(Debug)]
pub struct RollbackFailed {
    pub item: String,
    pub reason: String,
}

impl StoredSecret {
    /// Delete what this run stored. `Ok` names what was removed.
    pub async fn roll_back(self) -> Result<String, RollbackFailed> {
        match self {
            Self::OnePassword { op, account, item } => {
                let name = format!(
                    "1Password item {} in vault {} (account {account})",
                    item.item_id, item.vault_id
                );
                match op.item_delete(&account, &item).await {
                    Ok(()) => Ok(name),
                    Err(e) => Err(RollbackFailed {
                        item: name,
                        reason: e.to_string(),
                    }),
                }
            }
            Self::Keychain { keychain, account } => {
                let name = keychain_item_name(&keychain, &account);
                match keychain.delete(&account).await {
                    Ok(()) => Ok(name),
                    Err(e) => Err(RollbackFailed {
                        item: format!("{name} (`{}`)", keychain.delete_hint(&account)),
                        reason: e.to_string(),
                    }),
                }
            }
        }
    }
}

fn keychain_item_name(keychain: &Keychain, account: &str) -> String {
    format!(
        "Keychain item (service '{}', account '{account}')",
        keychain.service()
    )
}

fn copy_secret(secret: &Secret) -> Secret {
    Secret::new(secret.expose().to_string())
}

fn store_failed(what: &str, e: StoreError) -> CliError {
    CliError::Failed(format!("{what}: {e}; nothing was written"))
}

impl ChosenSource {
    /// The password to verify with, obtained in memory: the variable's value,
    /// the output of one run of the command (or `op read`), or a copy of the
    /// typed password.
    pub async fn password(&self, account: &str) -> Result<Secret, CliError> {
        match self {
            Self::Env(var) => std::env::var(var).map(Secret::new).map_err(|_| {
                CliError::Failed(format!(
                    "environment variable '{var}' is not set (or not valid UTF-8); set it, or \
                     pass --no-verify to write the account without checking it"
                ))
            }),
            Self::Command(argv) | Self::OnePasswordItem(argv) => {
                run_password_command(argv, DEFAULT_COMMAND_TIMEOUT)
                    .await
                    .map_err(|e| {
                        CliError::Failed(format!(
                            "account '{account}': the password command failed: {e}"
                        ))
                    })
            }
            Self::OnePasswordNew { password, .. } | Self::Keychain { password, .. } => {
                Ok(copy_secret(password))
            }
        }
    }

    /// The typed password of a storing source, known without running anything.
    fn known_password(&self) -> Option<Secret> {
        match self {
            Self::OnePasswordNew { password, .. } | Self::Keychain { password, .. } => {
                Some(copy_secret(password))
            }
            _ => None,
        }
    }

    /// Checks that need no secret, run before the credential check: an
    /// existing Keychain item needs `--force`, and `--force` never overwrites
    /// an item another account in the config reads.
    async fn preflight(&self, name: &str, others: &[AccountEntry]) -> Result<(), CliError> {
        let Self::Keychain {
            keychain, force, ..
        } = self
        else {
            return Ok(());
        };
        if let Some(other) = others.iter().find(|a| match &a.password {
            PasswordSetting::Command(argv) => keychain.item_of(argv) == Some(name),
            _ => false,
        }) {
            return Err(CliError::Usage(format!(
                "the {} is the password source of account '{}'; pick another name",
                keychain_item_name(keychain, name),
                other.name
            )));
        }
        let exists = keychain
            .exists(name)
            .await
            .map_err(|e| store_failed("checking the Keychain failed", e))?;
        if exists && !force {
            return Err(CliError::Usage(format!(
                "a {} already exists; pass --force to overwrite it",
                keychain_item_name(keychain, name)
            )));
        }
        Ok(())
    }

    /// Store the secret for sources that hold one, and return the setting to
    /// write plus the handle that undoes the store. `entry` gives the account
    /// name, URL and username (the password setting in it is ignored).
    pub async fn store(
        &self,
        entry: &AccountEntry,
    ) -> Result<(PasswordSetting, Option<StoredSecret>), CliError> {
        match self {
            Self::Env(var) => Ok((PasswordSetting::Env(var.clone()), None)),
            Self::Command(argv) | Self::OnePasswordItem(argv) => {
                Ok((PasswordSetting::Command(argv.clone()), None))
            }
            Self::OnePasswordNew {
                op,
                account,
                vault,
                password,
            } => {
                let title = format!("stalwart-mcp {}", entry.name);
                let item = op
                    .item_create(
                        account,
                        vault,
                        &NewLogin {
                            title: &title,
                            username: &entry.username,
                            url: &entry.url,
                            password,
                        },
                    )
                    .await
                    .map_err(|e| store_failed("creating the 1Password item failed", e))?;
                let argv = op.read_command(
                    account,
                    &OpReference::password_of(&item.vault_id, &item.item_id),
                );
                let stored = StoredSecret::OnePassword {
                    op: op.clone(),
                    account: account.clone(),
                    item,
                };
                Ok((PasswordSetting::Command(argv), Some(stored)))
            }
            Self::Keychain {
                keychain,
                password,
                force,
            } => {
                let exists = keychain
                    .exists(&entry.name)
                    .await
                    .map_err(|e| store_failed("checking the Keychain failed", e))?;
                if exists && !force {
                    return Err(CliError::Usage(format!(
                        "a {} already exists; pass --force to overwrite it",
                        keychain_item_name(keychain, &entry.name)
                    )));
                }
                keychain
                    .store(&entry.name, password, exists)
                    .await
                    .map_err(|e| store_failed("storing the password in the Keychain failed", e))?;
                let setting = PasswordSetting::Command(keychain.password_command(&entry.name));
                // An overwritten item is not ours to delete on rollback.
                let stored = (!exists).then(|| StoredSecret::Keychain {
                    keychain: keychain.clone(),
                    account: entry.name.clone(),
                });
                Ok((setting, stored))
            }
        }
    }
}

/// What [`choose_source`] needs besides the flags.
#[derive(Debug)]
pub struct SourceContext<'a> {
    /// The account's present setting (`edit`), used for prompt defaults.
    pub current: Option<&'a PasswordSetting>,
    /// False for `edit`, where no source flag means "keep it".
    pub required: bool,
    /// Host of the mail server URL, to find matching 1Password items.
    pub mail_host: &'a str,
    pub stores: &'a SecretStores,
}

/// Turn the source flags (and, when interactive, answers) into a source.
pub async fn choose_source(
    args: &SourceArgs,
    ctx: &SourceContext<'_>,
    prompter: &mut impl Prompter,
) -> Result<Option<ChosenSource>, CliError> {
    let (current, required) = (ctx.current, ctx.required);
    let inferred = if args.password_env.is_some() {
        Some((SourceKind::Env, "--password-env"))
    } else if !args.password_command.is_empty() {
        Some((SourceKind::Command, "--password-command"))
    } else if args.op_reference.is_some() {
        Some((SourceKind::OnePassword, "--op-reference"))
    } else if args.op_vault.is_some() {
        Some((SourceKind::OnePassword, "--op-vault"))
    } else {
        None
    };
    let kind = match (args.password_source, inferred) {
        (Some(kind), Some((other, flag))) if kind != other => {
            return Err(CliError::Usage(format!(
                "{flag} does not go with --password-source {}",
                kind.as_str()
            )));
        }
        (Some(kind), _) => Some(kind),
        (None, inferred) => inferred.map(|(kind, _)| kind),
    };
    if args.password_stdin && matches!(kind, Some(SourceKind::Env | SourceKind::Command)) {
        return Err(CliError::Usage(format!(
            "--password-stdin does not go with --password-source {}",
            kind.map(SourceKind::as_str).unwrap_or_default()
        )));
    }
    if args.force && kind.is_some_and(|k| k != SourceKind::Keychain) {
        return Err(CliError::Usage(
            "--force only goes with --password-source keychain".into(),
        ));
    }
    let kind = match kind {
        Some(kind) => kind,
        None if args.password_stdin => {
            return Err(CliError::Usage(
                "--password-stdin needs --password-source 1password or keychain".into(),
            ));
        }
        None if !required => return Ok(None),
        None => ask_source_kind(ctx.stores, prompter).await?,
    };
    match kind {
        SourceKind::OnePassword => one_password_source(args, ctx, prompter).await.map(Some),
        SourceKind::Keychain => keychain_source(args, ctx.stores, prompter).map(Some),
        SourceKind::Env => {
            let default = current
                .and_then(PasswordSetting::env_var)
                .unwrap_or(DEFAULT_PASSWORD_ENV);
            let var = required_value(
                args.password_env.clone(),
                "--password-env",
                "Environment variable holding the password",
                Some(default),
                prompter,
            )?;
            validate_env_name(&var)?;
            Ok(Some(ChosenSource::Env(var)))
        }
        SourceKind::Command => {
            let mut argv = if args.password_command.is_empty() {
                let line = required_value(
                    None,
                    "--password-command",
                    "Command that prints the password (program and arguments separated by \
                     spaces; use --password-command per argument for arguments with spaces)",
                    None,
                    prompter,
                )?;
                line.split_whitespace().map(str::to_string).collect()
            } else {
                args.password_command.clone()
            };
            let program = argv
                .first()
                .ok_or_else(|| CliError::Usage("--password-command is empty".into()))?;
            let cwd = std::env::current_dir()
                .map_err(|e| CliError::Usage(format!("cannot read the current directory: {e}")))?;
            let resolved = resolve_program(program, std::env::var_os("PATH").as_deref(), &cwd)?;
            argv[0] = resolved;
            Ok(Some(ChosenSource::Command(argv)))
        }
    }
}

/// Ask for the source. The suggested default is 1Password when `op` is found
/// and has an account, else the Keychain (macOS), else env. Never chosen
/// silently: without a terminal this is an error naming the flag.
async fn ask_source_kind(
    stores: &SecretStores,
    prompter: &mut impl Prompter,
) -> Result<SourceKind, CliError> {
    if !prompter.interactive() {
        return Err(CliError::Usage(
            "missing --password-source (1password, keychain, env or command) and no terminal to \
             ask on"
                .into(),
        ));
    }
    let op_ready = match &stores.op {
        Some(op) => op
            .accounts()
            .await
            .is_ok_and(|accounts| accounts.iter().any(|a| a.id().is_some())),
        None => false,
    };
    let default = if op_ready {
        SourceKind::OnePassword
    } else if stores.keychain.is_some() {
        SourceKind::Keychain
    } else {
        SourceKind::Env
    };
    let offered: Vec<&str> = [
        (op_ready, SourceKind::OnePassword),
        (stores.keychain.is_some(), SourceKind::Keychain),
        (true, SourceKind::Env),
        (true, SourceKind::Command),
    ]
    .into_iter()
    .filter_map(|(available, kind)| available.then_some(kind.as_str()))
    .collect();
    let answer = prompter.ask(
        &format!("Password source ({})", offered.join(", ")),
        Some(default.as_str()),
    )?;
    let answer = answer.trim();
    let answer = if answer.is_empty() {
        default.as_str()
    } else {
        answer
    };
    SourceKind::from_str(answer, true)
        .map_err(|_| CliError::Usage(format!("unknown password source '{answer}'")))
}

/// The password to store: from stdin with `--password-stdin`, else typed
/// on the terminal (not echoed).
fn typed_password(
    args: &SourceArgs,
    question: &str,
    prompter: &mut impl Prompter,
) -> Result<Secret, CliError> {
    if args.password_stdin {
        return prompter.read_password_stdin();
    }
    if !prompter.interactive() {
        return Err(CliError::Usage(
            "missing --password-stdin and no terminal to type the password on".into(),
        ));
    }
    let password = prompter.ask_secret(question)?;
    if password.expose().is_empty() {
        return Err(CliError::Usage("no password given".into()));
    }
    Ok(password)
}

fn keychain_source(
    args: &SourceArgs,
    stores: &SecretStores,
    prompter: &mut impl Prompter,
) -> Result<ChosenSource, CliError> {
    let keychain = stores.keychain.clone().ok_or_else(|| {
        CliError::Usage(
            "the Keychain source is only available on macOS; use --password-source 1password, \
             env or command"
                .into(),
        )
    })?;
    let password = typed_password(
        args,
        "Mailbox password (stored in the macOS Keychain)",
        prompter,
    )?;
    check_keychain_password(&password).map_err(|e| CliError::Usage(e.to_string()))?;
    Ok(ChosenSource::Keychain {
        keychain,
        password,
        force: args.force,
    })
}

async fn one_password_source(
    args: &SourceArgs,
    ctx: &SourceContext<'_>,
    prompter: &mut impl Prompter,
) -> Result<ChosenSource, CliError> {
    let op = ctx.stores.op.clone().ok_or_else(|| {
        CliError::Usage(
            "the 1Password CLI (op) was not found on PATH, in /opt/homebrew/bin or in \
             /usr/local/bin; install it and switch on the CLI integration in the 1Password app, \
             or pick another --password-source"
                .into(),
        )
    })?;
    let accounts = op
        .accounts()
        .await
        .map_err(|e| CliError::Failed(format!("1Password: {e}")))?;
    let account = pick_op_account(&accounts, prompter)?;

    if let Some(reference) = &args.op_reference {
        return reference_source(&op, &account, reference).await;
    }
    let create = if args.op_vault.is_some() || args.password_stdin {
        true
    } else if !prompter.interactive() {
        return Err(CliError::Usage(
            "missing --op-reference (an existing item) or --op-vault (a new item) and no \
             terminal to ask on"
                .into(),
        ));
    } else {
        let answer = prompter.ask(
            "Use an existing 1Password item or create a new one (existing, new)",
            Some("existing"),
        )?;
        match answer.trim().to_ascii_lowercase().as_str() {
            "" | "existing" | "e" => false,
            "new" | "n" => true,
            other => {
                return Err(CliError::Usage(format!(
                    "unknown answer '{other}'; expected existing or new"
                )));
            }
        }
    };
    if !create {
        return pick_item_source(&op, &account, ctx.mail_host, prompter).await;
    }
    let vault = required_value(
        args.op_vault.clone(),
        "--op-vault",
        "1Password vault for the new item",
        None,
        prompter,
    )?;
    let password = typed_password(
        args,
        "Mailbox password (stored in a new 1Password item)",
        prompter,
    )?;
    Ok(ChosenSource::OnePasswordNew {
        op,
        account,
        vault,
        password,
    })
}

/// The `--account` id: the only account, or the one picked on the terminal.
fn pick_op_account(
    accounts: &[OpAccount],
    prompter: &mut impl Prompter,
) -> Result<String, CliError> {
    let usable: Vec<(&OpAccount, &str)> = accounts
        .iter()
        .filter_map(|a| a.id().map(|id| (a, id)))
        .collect();
    match usable[..] {
        [] => Err(CliError::Failed(
            "1Password: op lists no accounts; sign in with `op signin` or switch on the CLI \
             integration in the 1Password app (Settings, Developer)"
                .into(),
        )),
        [(_, id)] => Ok(id.to_string()),
        _ if !prompter.interactive() => Err(CliError::Usage(
            "several 1Password accounts are set up and there is no terminal to pick one on".into(),
        )),
        _ => {
            let mut question = String::from("1Password accounts:\n");
            for (n, (account, _)) in usable.iter().enumerate() {
                question.push_str(&format!(
                    "  {}) {} ({})\n",
                    n + 1,
                    printable(&account.url),
                    printable(&account.email)
                ));
            }
            question.push_str("Number of the account");
            let answer = prompter.ask(&question, Some("1"))?;
            let index = pick_index(&answer, usable.len())?;
            Ok(usable[index].1.to_string())
        }
    }
}

/// A 0-based index from a 1-based answer (empty means 1).
fn pick_index(answer: &str, len: usize) -> Result<usize, CliError> {
    let answer = answer.trim();
    let answer = if answer.is_empty() { "1" } else { answer };
    answer
        .parse::<usize>()
        .ok()
        .filter(|n| (1..=len).contains(n))
        .map(|n| n - 1)
        .ok_or_else(|| CliError::Usage(format!("'{answer}' is not a number from 1 to {len}")))
}

/// Text from `op` output shown on the terminal, without control characters.
fn printable(text: &str) -> String {
    text.chars().filter(|c| !c.is_control()).collect()
}

/// Offer the Login items that match the mail host; the answer is a number or
/// an `op://` reference.
async fn pick_item_source(
    op: &OnePassword,
    account: &str,
    mail_host: &str,
    prompter: &mut impl Prompter,
) -> Result<ChosenSource, CliError> {
    let items = op
        .item_list(account)
        .await
        .map_err(|e| CliError::Failed(format!("1Password: {e}")))?;
    let matches = matching_items(&items, mail_host);
    if matches.is_empty() {
        let reference = required_value(
            None,
            "--op-reference",
            &format!(
                "No 1Password Login item matches {mail_host}; reference of the password \
                 (op://vault/item/field)"
            ),
            None,
            prompter,
        )?;
        return reference_source(op, account, &reference).await;
    }
    let mut question = format!("1Password Login items matching {mail_host}:\n");
    for (n, item) in matches.iter().enumerate() {
        question.push_str(&format!(
            "  {}) {} (vault {})\n",
            n + 1,
            printable(&item.title),
            printable(&item.vault.name)
        ));
    }
    question.push_str("Number of the item, or an op:// reference");
    let answer = prompter.ask(&question, Some("1"))?;
    if answer.trim().starts_with("op://") {
        return reference_source(op, account, answer.trim()).await;
    }
    let item = matches[pick_index(&answer, matches.len())?];
    let reference = OpReference::password_of(&item.vault.id, &item.id).to_uri();
    reference_source(op, account, &reference).await
}

/// Resolve a reference to ids and build the `op read` argv.
async fn reference_source(
    op: &OnePassword,
    account: &str,
    reference: &str,
) -> Result<ChosenSource, CliError> {
    let parsed = OpReference::parse(reference).map_err(|e| CliError::Usage(e.to_string()))?;
    let resolved = op
        .resolve(account, &parsed)
        .await
        .map_err(|e| CliError::Failed(format!("1Password: {e}")))?;
    Ok(ChosenSource::OnePasswordItem(
        op.read_command(account, &resolved),
    ))
}

/// Resolve `program` to an absolute path: a path with a `/` is taken as is
/// (relative to `cwd`), a bare name is looked up in the absolute entries of
/// `path_var`. The result must be an executable regular file.
pub fn resolve_program(
    program: &str,
    path_var: Option<&OsStr>,
    cwd: &Path,
) -> Result<String, CliError> {
    if program.is_empty() {
        return Err(CliError::Usage(
            "--password-command has an empty program".into(),
        ));
    }
    let found = if program.contains('/') {
        let candidate = Path::new(program);
        let candidate = if candidate.is_absolute() {
            candidate.to_path_buf()
        } else {
            cwd.join(candidate)
        };
        if !is_executable_file(&candidate) {
            return Err(CliError::Usage(format!(
                "password command program {} is not an executable file",
                candidate.display()
            )));
        }
        candidate
    } else {
        path_var
            .into_iter()
            .flat_map(std::env::split_paths)
            .filter(|dir| dir.is_absolute())
            .map(|dir| dir.join(program))
            .find(|candidate| is_executable_file(candidate))
            .ok_or_else(|| {
                CliError::Usage(format!(
                    "password command program '{program}' was not found on PATH; give its \
                     absolute path"
                ))
            })?
    };
    found
        .into_os_string()
        .into_string()
        .map_err(|_| CliError::Usage("the password command path is not valid UTF-8".into()))
}

/// New and renamed account names: `[A-Za-z0-9_-]{1,64}`.
pub fn validate_account_name(name: &str) -> Result<(), CliError> {
    let valid = !name.is_empty()
        && name.len() <= MAX_NAME_LEN
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if valid {
        Ok(())
    } else {
        Err(CliError::Usage(format!(
            "invalid account name '{name}': use 1 to {MAX_NAME_LEN} letters, digits, '-' or '_'"
        )))
    }
}

fn validate_url(url: &str) -> Result<(), CliError> {
    let parsed =
        url::Url::parse(url).map_err(|e| CliError::Usage(format!("invalid --url '{url}': {e}")))?;
    if !matches!(parsed.scheme(), "http" | "https") || parsed.host_str().is_none() {
        return Err(CliError::Usage(format!(
            "invalid --url '{url}': expected http(s)://host"
        )));
    }
    Ok(())
}

fn validate_username(username: &str) -> Result<(), CliError> {
    if username.trim().is_empty() {
        return Err(CliError::Usage("--username is empty".into()));
    }
    Ok(())
}

fn validate_env_name(var: &str) -> Result<(), CliError> {
    let mut bytes = var.bytes();
    let valid = bytes
        .next()
        .is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_');
    if valid {
        Ok(())
    } else {
        Err(CliError::Usage(format!(
            "invalid --password-env '{var}': use letters, digits and '_', not starting with a digit"
        )))
    }
}

/// `given`, or the answer to `question` when a terminal is available;
/// otherwise an error naming `flag`.
fn required_value(
    given: Option<String>,
    flag: &str,
    question: &str,
    default: Option<&str>,
    prompter: &mut impl Prompter,
) -> Result<String, CliError> {
    if let Some(value) = given {
        return Ok(value);
    }
    if !prompter.interactive() {
        return Err(CliError::Usage(format!(
            "missing {flag} and no terminal to ask on"
        )));
    }
    let answer = prompter.ask(question, default)?;
    let answer = answer.trim();
    match (answer.is_empty(), default) {
        (false, _) => Ok(answer.to_string()),
        (true, Some(default)) => Ok(default.to_string()),
        (true, None) => Err(CliError::Usage(format!("no value given for {flag}"))),
    }
}

/// Ask `question` unless `yes`; without a terminal an error names `--yes`.
fn confirm(yes: bool, question: &str, prompter: &mut impl Prompter) -> Result<(), CliError> {
    if yes {
        return Ok(());
    }
    if !prompter.interactive() {
        return Err(CliError::Usage(
            "confirmation needed and no terminal to ask on; pass --yes".into(),
        ));
    }
    if prompter.confirm(question)? {
        Ok(())
    } else {
        Err(CliError::Aborted)
    }
}

/// The runtime view of an entry, as `serve` would load it.
fn account_config(entry: &AccountEntry) -> AccountConfig {
    let (password_env, password_command) = match &entry.password {
        PasswordSetting::DefaultEnv => (None, None),
        PasswordSetting::Env(var) => (Some(var.clone()), None),
        PasswordSetting::Command(argv) => (None, Some(argv.clone())),
    };
    AccountConfig {
        name: entry.name.clone(),
        url: entry.url.clone(),
        username: entry.username.clone(),
        password_env,
        password_command,
    }
}

async fn verify(
    verifier: &impl Verifier,
    account: &AccountConfig,
    password: &Secret,
    out: &mut impl Write,
) -> Result<(), CliError> {
    writeln!(
        out,
        "Checking the credentials of '{}' at {} ...",
        account.name, account.url
    )?;
    verifier.verify(account, password).await.map_err(|e| {
        CliError::Failed(format!(
            "account '{}': the credential check failed: {e}; nothing was written",
            account.name
        ))
    })
}

/// Load the saved config the way `serve` does (including the permission
/// check) and run the stored source once more; it must return the password
/// that was verified.
async fn final_check(path: &Path, name: &str, expected: &Secret) -> Result<(), CliError> {
    let config = AppConfig::load_allow_empty(Some(&path.to_path_buf()))?;
    let account = config
        .accounts
        .iter()
        .find(|a| a.name == name)
        .ok_or_else(|| CliError::Failed(format!("account '{name}' is missing after the write")))?;
    let password = account.resolve_password().await?;
    if password.expose() != expected.expose() {
        return Err(CliError::Failed(format!(
            "the stored password source of '{name}' returned a different password than the one \
             that was verified"
        )));
    }
    Ok(())
}

/// Undo a store after a later step failed; returns a sentence for the error.
async fn roll_back(stored: Option<StoredSecret>) -> String {
    let Some(stored) = stored else {
        return String::new();
    };
    match stored.roll_back().await {
        Ok(item) => format!(" The stored secret ({item}) was removed again."),
        Err(failed) => format!(
            " Removing the stored secret failed ({}); remove {} by hand.",
            failed.reason, failed.item
        ),
    }
}

/// The host of a validated URL, lowercased (empty if it has none).
fn mail_host(url: &str) -> String {
    url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
        .unwrap_or_default()
}

async fn add(
    args: AddArgs,
    path: &Path,
    stores: &SecretStores,
    prompter: &mut impl Prompter,
    verifier: &impl Verifier,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let mut doc = ConfigDocument::load_or_new(path)?;
    let existing = doc.accounts()?;

    let name = required_value(args.name, "--name", "Account name", None, prompter)?;
    validate_account_name(&name)?;
    if existing.iter().any(|a| a.name == name) {
        return Err(CliError::Usage(format!(
            "an account named '{name}' already exists in {}; use `stalwart-mcp account edit {name}`",
            path.display()
        )));
    }
    let url = required_value(
        args.url,
        "--url",
        "JMAP server URL (e.g. https://mail.example.com)",
        None,
        prompter,
    )?;
    validate_url(&url)?;
    let username = required_value(args.username, "--username", "Username", None, prompter)?;
    validate_username(&username)?;
    let host = mail_host(&url);
    let ctx = SourceContext {
        current: None,
        required: true,
        mail_host: &host,
        stores,
    };
    let source = choose_source(&args.source, &ctx, prompter)
        .await?
        .ok_or_else(|| CliError::Usage("missing --password-source".into()))?;
    source.preflight(&name, &existing).await?;

    let probe = AccountEntry {
        name: name.clone(),
        url: url.clone(),
        username: username.clone(),
        password: PasswordSetting::DefaultEnv,
    };
    let password = if args.no_verify {
        // A typed password is still compared with what the store returns.
        source.known_password()
    } else {
        let password = source.password(&name).await?;
        verify(verifier, &account_config(&probe), &password, out).await?;
        Some(password)
    };

    let make_default = args.default || existing.is_empty();
    confirm(
        args.yes,
        &format!("Add account '{name}' to {}?", path.display()),
        prompter,
    )?;

    let (setting, stored) = source.store(&probe).await?;
    let entry = AccountEntry {
        password: setting,
        ..probe
    };
    let previous_default = doc.default_account().map(str::to_string);
    if let Err(e) = write_new_account(&mut doc, &entry, make_default) {
        let note = roll_back(stored).await;
        return Err(CliError::Failed(format!(
            "could not write {}: {e}.{note}",
            path.display()
        )));
    }

    if let Some(password) = &password
        && let Err(e) = final_check(path, &name, password).await
    {
        let undo = undo_add(&mut doc, &name, previous_default.as_deref());
        let note = roll_back(stored).await;
        return Err(CliError::Failed(format!(
            "the final check of '{name}' failed: {e}. {undo}{note}"
        )));
    }

    writeln!(
        out,
        "Added account '{name}' ({}) to {}",
        SourceDescription::of(&entry.password),
        path.display()
    )?;
    if make_default {
        writeln!(out, "'{name}' is the default account")?;
    }
    warn_about_program(&entry.password, out)?;
    if args.no_verify {
        writeln!(
            out,
            "Credentials not checked (--no-verify); run `stalwart-mcp account test {name}`"
        )?;
    }
    Ok(())
}

/// Print [`program_permission_warnings`] for the program of a written
/// `password_command` (Unix only; never a refusal).
fn warn_about_program(setting: &PasswordSetting, out: &mut impl Write) -> Result<(), CliError> {
    if let PasswordSetting::Command(argv) = setting
        && let Some(program) = argv.first()
    {
        for warning in program_permission_warnings(program) {
            writeln!(out, "{warning}")?;
        }
    }
    Ok(())
}

fn write_new_account(
    doc: &mut ConfigDocument,
    entry: &AccountEntry,
    make_default: bool,
) -> Result<(), CliError> {
    doc.add_account(entry)?;
    if make_default {
        doc.set_default(&entry.name)?;
    }
    doc.save()?;
    Ok(())
}

/// Put `default_account` back to `previous` when it was set and moved.
fn restore_default(doc: &mut ConfigDocument, previous: Option<&str>) -> Result<(), CliError> {
    if let Some(previous) = previous
        && doc.default_account() != Some(previous)
    {
        doc.set_default(previous)?;
    }
    Ok(())
}

fn remove_new_account(
    doc: &mut ConfigDocument,
    name: &str,
    previous_default: Option<&str>,
) -> Result<(), CliError> {
    doc.remove_account(name)?;
    restore_default(doc, previous_default)?;
    doc.save()?;
    Ok(())
}

/// Remove the account `add` just wrote; returns a sentence for the error.
fn undo_add(doc: &mut ConfigDocument, name: &str, previous_default: Option<&str>) -> String {
    match remove_new_account(doc, name, previous_default) {
        Ok(()) => "The account was removed from the config again.".into(),
        Err(e) => format!(
            "Removing it from the config again failed ({e}); run `stalwart-mcp account remove {name}`."
        ),
    }
}

/// The Keychain item a setting reads, when it has the exact shape this CLI
/// writes for the configured program and service.
fn keychain_item(stores: &SecretStores, setting: &PasswordSetting) -> Option<(Keychain, String)> {
    let keychain = stores.keychain.as_ref()?;
    let PasswordSetting::Command(argv) = setting else {
        return None;
    };
    keychain
        .item_of(argv)
        .map(|account| (keychain.clone(), account.to_string()))
}

async fn edit(
    args: EditArgs,
    path: &Path,
    stores: &SecretStores,
    prompter: &mut impl Prompter,
    verifier: &impl Verifier,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let mut doc = ConfigDocument::load_or_new(path)?;
    let accounts = doc.accounts()?;
    let current = accounts
        .iter()
        .find(|a| a.name == args.name)
        .cloned()
        .ok_or_else(|| no_account(&args.name, path))?;

    if let Some(new_name) = &args.rename {
        validate_account_name(new_name)?;
        if new_name != &current.name && accounts.iter().any(|a| &a.name == new_name) {
            return Err(CliError::Usage(format!(
                "an account named '{new_name}' already exists"
            )));
        }
    }
    if let Some(url) = &args.url {
        validate_url(url)?;
    }
    if let Some(username) = &args.username {
        validate_username(username)?;
    }
    let host = mail_host(args.url.as_deref().unwrap_or(&current.url));
    let ctx = SourceContext {
        current: Some(&current.password),
        required: false,
        mail_host: &host,
        stores,
    };
    let mut source = choose_source(&args.source, &ctx, prompter).await?;
    if args.rename.is_none()
        && args.url.is_none()
        && args.username.is_none()
        && source.is_none()
        && !args.default
    {
        return Err(CliError::Usage(
            "nothing to change; pass --rename, --url, --username, --default or a password flag"
                .into(),
        ));
    }

    let new_name = args.rename.clone().unwrap_or_else(|| current.name.clone());
    let explicit_source = source.is_some();
    let old_item = keychain_item(stores, &current.password);

    // A rename moves the account's own Keychain item to the new name, so the
    // item keeps matching the account (see the module docs).
    let mut moved_from = None;
    if source.is_none()
        && new_name != current.name
        && let Some((keychain, item_account)) = &old_item
        && *item_account == current.name
    {
        let password = account_config(&current)
            .resolve_password()
            .await
            .map_err(|e| {
                CliError::Failed(format!(
                    "reading the Keychain item of '{}' to move it failed: {e}; nothing was changed",
                    current.name
                ))
            })?;
        source = Some(ChosenSource::Keychain {
            keychain: keychain.clone(),
            password,
            force: args.source.force,
        });
        moved_from = Some((keychain.clone(), current.name.clone()));
    }
    if let Some(source) = &source {
        let others: Vec<AccountEntry> = accounts
            .iter()
            .filter(|a| a.name != current.name)
            .cloned()
            .collect();
        source.preflight(&new_name, &others).await?;
    }

    let url_changed = args.url.as_ref().is_some_and(|u| u != &current.url);
    let username_changed = args
        .username
        .as_ref()
        .is_some_and(|u| u != &current.username);
    let probe = AccountEntry {
        name: new_name.clone(),
        url: args.url.clone().unwrap_or_else(|| current.url.clone()),
        username: args
            .username
            .clone()
            .unwrap_or_else(|| current.username.clone()),
        password: current.password.clone(),
    };

    let password = if !args.no_verify && (url_changed || username_changed || explicit_source) {
        let password = match &source {
            Some(source) => source.password(&new_name).await?,
            None => account_config(&probe).resolve_password().await?,
        };
        verify(verifier, &account_config(&probe), &password, out).await?;
        Some(password)
    } else {
        // A typed (or moved) password is still compared with what the store
        // returns.
        source.as_ref().and_then(ChosenSource::known_password)
    };

    confirm(
        args.yes,
        &format!("Change account '{}' in {}?", current.name, path.display()),
        prompter,
    )?;

    let (setting, stored) = match &source {
        Some(source) => {
            let (setting, stored) = source.store(&probe).await?;
            (Some(setting), stored)
        }
        None => (None, None),
    };
    let previous_default = doc.default_account().map(str::to_string);
    let update = AccountUpdate {
        name: args.rename.clone().filter(|n| n != &current.name),
        url: args.url.clone(),
        username: args.username.clone(),
        password: setting.clone(),
    };
    let default = args.default.then_some(new_name.as_str());
    if let Err(e) = write_update(&mut doc, &current.name, &update, default) {
        let note = roll_back(stored).await;
        return Err(CliError::Failed(format!(
            "could not write {}: {e}.{note}",
            path.display()
        )));
    }

    if let Some(password) = &password
        && let Err(e) = final_check(path, &new_name, password).await
    {
        let undo = undo_edit(&mut doc, &new_name, &current, previous_default.as_deref());
        let note = roll_back(stored).await;
        return Err(CliError::Failed(format!(
            "the final check of '{new_name}' failed: {e}. {undo}{note}"
        )));
    }

    writeln!(out, "Updated account '{new_name}' in {}", path.display())?;
    if new_name != current.name {
        writeln!(out, "Renamed '{}' to '{new_name}'", current.name)?;
        if previous_default.as_deref() == Some(current.name.as_str()) {
            writeln!(out, "'{new_name}' stays the default account")?;
        }
    }
    if let Some(setting) = &setting {
        writeln!(out, "Password source: {}", SourceDescription::of(setting))?;
        warn_about_program(setting, out)?;
    }
    if args.default {
        writeln!(out, "'{new_name}' is the default account")?;
    }
    if let Some((keychain, old)) = moved_from {
        // The config now reads the new item; the old one is no longer used.
        match keychain.delete(&old).await {
            Ok(()) => writeln!(
                out,
                "Moved the Keychain item from account '{old}' to '{new_name}'"
            )?,
            Err(e) => writeln!(
                out,
                "The old {} could not be deleted ({e}); delete it with `{}`",
                keychain_item_name(&keychain, &old),
                keychain.delete_hint(&old)
            )?,
        }
    } else if let (Some(setting), Some((keychain, old))) = (&setting, &old_item)
        && keychain_item(stores, setting).is_none_or(|(_, account)| account != *old)
    {
        writeln!(
            out,
            "The {} is no longer used by this account and was kept; delete it with `{}` if \
             nothing else needs it",
            keychain_item_name(keychain, old),
            keychain.delete_hint(old)
        )?;
    }
    Ok(())
}

fn write_update(
    doc: &mut ConfigDocument,
    name: &str,
    update: &AccountUpdate,
    default: Option<&str>,
) -> Result<(), CliError> {
    doc.update_account(name, update)?;
    if let Some(default) = default {
        doc.set_default(default)?;
    }
    doc.save()?;
    Ok(())
}

fn restore_account(
    doc: &mut ConfigDocument,
    name: &str,
    before: &AccountEntry,
    previous_default: Option<&str>,
) -> Result<(), CliError> {
    doc.update_account(
        name,
        &AccountUpdate {
            name: Some(before.name.clone()),
            url: Some(before.url.clone()),
            username: Some(before.username.clone()),
            password: Some(before.password.clone()),
        },
    )?;
    restore_default(doc, previous_default)?;
    doc.save()?;
    Ok(())
}

/// Put the account back as it was before `edit`; returns a sentence.
fn undo_edit(
    doc: &mut ConfigDocument,
    name: &str,
    before: &AccountEntry,
    previous_default: Option<&str>,
) -> String {
    match restore_account(doc, name, before, previous_default) {
        Ok(()) => "The account was changed back.".into(),
        Err(e) => format!("Changing it back failed ({e}); check the account with `account list`."),
    }
}

/// Remove an account. A Keychain item is deleted only with `--delete-secret`
/// or a confirmed prompt, and only when the stored argv has exactly the shape
/// this CLI writes (program, service); the item is the one named by that
/// argv's `-s` and `-a`, not derived from the account name. A 1Password item
/// is never deleted.
async fn remove(
    args: RemoveArgs,
    path: &Path,
    stores: &SecretStores,
    prompter: &mut impl Prompter,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let mut doc = ConfigDocument::load_or_new(path)?;
    let accounts = doc.accounts()?;
    let entry = accounts
        .iter()
        .find(|a| a.name == args.name)
        .ok_or_else(|| no_account(&args.name, path))?;
    let item = keychain_item(stores, &entry.password);
    // Another account that reads the same item keeps it alive.
    let shared_with = item.as_ref().and_then(|(_, account)| {
        accounts
            .iter()
            .filter(|a| a.name != args.name)
            .find(|a| {
                keychain_item(stores, &a.password).is_some_and(|(_, other)| other == *account)
            })
            .map(|a| a.name.clone())
    });
    if args.delete_secret
        && let (Some((keychain, account)), Some(other)) = (&item, &shared_with)
    {
        return Err(CliError::Usage(format!(
            "the {} is also the password source of account '{other}', so it is not deleted; run \
             the command without --delete-secret",
            keychain_item_name(keychain, account)
        )));
    }

    if args.delete_secret && item.is_none() {
        return Err(match SourceDescription::of(&entry.password) {
            SourceDescription::Keychain if stores.keychain.is_none() => CliError::Usage(
                "the macOS Keychain is not available on this system, so no item can be deleted; \
                 run the command without --delete-secret"
                    .into(),
            ),
            SourceDescription::Keychain => CliError::Usage(format!(
                "the password_command of '{}' is not exactly the Keychain command stalwart-mcp \
                 writes (service '{}'), so no item is deleted; run the command without \
                 --delete-secret and delete the item by hand",
                args.name,
                stores
                    .keychain
                    .as_ref()
                    .map(Keychain::service)
                    .unwrap_or(KEYCHAIN_SERVICE)
            )),
            SourceDescription::OnePassword => CliError::Usage(
                "1Password items are never deleted by stalwart-mcp; delete it in 1Password if \
                 you no longer need it, and run the command without --delete-secret"
                    .into(),
            ),
            other => CliError::Usage(format!(
                "'{}' has no stored secret to delete (source: {other}); run the command without \
                 --delete-secret",
                args.name
            )),
        });
    }

    confirm(
        args.yes,
        &format!("Remove account '{}' from {}?", args.name, path.display()),
        prompter,
    )?;
    let delete = match &item {
        _ if shared_with.is_some() => false,
        Some(_) if args.delete_secret => true,
        Some((keychain, account)) if !args.yes && prompter.interactive() => prompter.confirm(
            &format!("Also delete the {}?", keychain_item_name(keychain, account)),
        )?,
        _ => false,
    };
    let change = doc.remove_account(&args.name)?;
    doc.save()?;

    writeln!(
        out,
        "Removed account '{}' from {}",
        args.name,
        path.display()
    )?;
    match change {
        DefaultAccountChange::Unchanged => {}
        DefaultAccountChange::Moved(next) => writeln!(
            out,
            "'{}' was the default account; the default is now '{next}'",
            args.name
        )?,
        DefaultAccountChange::Cleared => {
            writeln!(out, "No accounts remain; default_account was removed")?;
        }
    }
    // The config no longer points at the item, so it is deleted last.
    if let Some((keychain, account)) = item {
        let name = keychain_item_name(&keychain, &account);
        if delete {
            keychain.delete(&account).await.map_err(|e| {
                CliError::Failed(format!(
                    "removed '{}' from {}, but deleting the {name} failed: {e}; delete it with \
                     `{}`",
                    args.name,
                    path.display(),
                    keychain.delete_hint(&account)
                ))
            })?;
            writeln!(out, "Deleted the {name}")?;
        } else if let Some(other) = &shared_with {
            writeln!(out, "Kept the {name}; account '{other}' still reads it")?;
        } else {
            writeln!(
                out,
                "Kept the {name}; delete it with `{}` if nothing else needs it",
                keychain.delete_hint(&account)
            )?;
        }
    }
    Ok(())
}

fn no_account(name: &str, path: &Path) -> CliError {
    CliError::Usage(format!("no account named '{name}' in {}", path.display()))
}

/// What `list` shows for a password setting. Never a secret, and for a
/// command only the program's file name, not its arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceDescription {
    Env(String),
    OnePassword,
    Keychain,
    Command(String),
}

impl SourceDescription {
    /// Recognises the argv shapes written for 1Password (`op read ...`) and
    /// the Keychain (`security find-generic-password ...`).
    pub fn of(setting: &PasswordSetting) -> Self {
        match setting {
            PasswordSetting::DefaultEnv => Self::Env(DEFAULT_PASSWORD_ENV.into()),
            PasswordSetting::Env(var) => Self::Env(var.clone()),
            PasswordSetting::Command(argv) => {
                let program = argv
                    .first()
                    .map(|p| {
                        Path::new(p)
                            .file_name()
                            .map(|n| n.to_string_lossy().into_owned())
                            .unwrap_or_else(|| p.clone())
                    })
                    .unwrap_or_default();
                let action = argv.get(1).map(String::as_str);
                match (program.as_str(), action) {
                    ("op", Some("read")) => Self::OnePassword,
                    ("security", Some("find-generic-password")) => Self::Keychain,
                    _ => Self::Command(program),
                }
            }
        }
    }

    fn kind(&self) -> &'static str {
        match self {
            Self::Env(_) => "env",
            Self::OnePassword => "1password",
            Self::Keychain => "keychain",
            Self::Command(_) => "command",
        }
    }

    fn to_json(&self) -> serde_json::Value {
        match self {
            Self::Env(var) => serde_json::json!({ "kind": self.kind(), "variable": var }),
            Self::Command(program) => {
                serde_json::json!({ "kind": self.kind(), "program": program })
            }
            Self::OnePassword | Self::Keychain => serde_json::json!({ "kind": self.kind() }),
        }
    }
}

impl fmt::Display for SourceDescription {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Env(var) => write!(f, "env {var}"),
            Self::Command(program) => write!(f, "command {program}"),
            Self::OnePassword | Self::Keychain => f.write_str(self.kind()),
        }
    }
}

fn list(path: &Path, json: bool, out: &mut impl Write) -> Result<(), CliError> {
    let doc = ConfigDocument::load_or_new(path)?;
    let accounts = doc.accounts()?;
    let default = doc.default_account();

    if json {
        let accounts: Vec<_> = accounts
            .iter()
            .map(|a| {
                serde_json::json!({
                    "name": a.name,
                    "url": a.url,
                    "username": a.username,
                    "default": default == Some(a.name.as_str()),
                    "password_source": SourceDescription::of(&a.password).to_json(),
                })
            })
            .collect();
        let value = serde_json::json!({
            "config": path.display().to_string(),
            "default_account": default,
            "accounts": accounts,
        });
        serde_json::to_writer_pretty(&mut *out, &value).map_err(|e| CliError::Output(e.into()))?;
        writeln!(out)?;
        return Ok(());
    }

    if accounts.is_empty() {
        writeln!(
            out,
            "No accounts in {}; add one with `stalwart-mcp account add`",
            path.display()
        )?;
        return Ok(());
    }
    let rows: Vec<[String; 4]> = accounts
        .iter()
        .map(|a| {
            [
                a.name.clone(),
                a.url.clone(),
                a.username.clone(),
                SourceDescription::of(&a.password).to_string(),
            ]
        })
        .collect();
    let header = ["NAME", "URL", "USERNAME", "PASSWORD"].map(String::from);
    let mut widths = [0usize; 3];
    for row in std::iter::once(&header).chain(&rows) {
        for (width, cell) in widths.iter_mut().zip(row) {
            *width = (*width).max(cell.chars().count());
        }
    }
    let [w0, w1, w2] = widths;
    let line = |marker: &str, row: &[String; 4]| {
        format!(
            "{marker} {:<w0$}  {:<w1$}  {:<w2$}  {}",
            row[0], row[1], row[2], row[3]
        )
    };
    writeln!(out, "{}", line(" ", &header).trim_end())?;
    for (account, row) in accounts.iter().zip(&rows) {
        let marker = if default == Some(account.name.as_str()) {
            "*"
        } else {
            " "
        };
        writeln!(out, "{}", line(marker, row).trim_end())?;
    }
    if default.is_some() {
        writeln!(out, "(* default account)")?;
    }
    Ok(())
}

async fn test(
    path: &Path,
    name: Option<&str>,
    verifier: &impl Verifier,
    out: &mut impl Write,
) -> Result<bool, CliError> {
    let config = AppConfig::load_allow_empty(Some(&path.to_path_buf()))?;
    let accounts: Vec<&AccountConfig> = match name {
        Some(name) => vec![
            config
                .accounts
                .iter()
                .find(|a| a.name == name)
                .ok_or_else(|| no_account(name, path))?,
        ],
        None => config.accounts.iter().collect(),
    };
    if accounts.is_empty() {
        return Err(CliError::Usage(format!(
            "no accounts in {}; add one with `stalwart-mcp account add`",
            path.display()
        )));
    }
    let mut all_ok = true;
    for account in accounts {
        let result = match account.resolve_password().await {
            Ok(password) => verifier.verify(account, &password).await,
            Err(e) => Err(e),
        };
        match result {
            Ok(()) => writeln!(out, "{}: ok", account.name)?,
            Err(e) => {
                all_ok = false;
                writeln!(out, "{}: {e}", account.name)?;
            }
        }
    }
    Ok(all_ok)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cli::{Cli, Commands};
    use crate::error::AppError;
    use clap::Parser;
    use std::cell::RefCell;
    use std::collections::VecDeque;
    use std::path::PathBuf;

    const FAKE: &str = "not-a-real-password";

    /// Scripted answers; records the questions asked and their defaults.
    #[derive(Debug, Default)]
    struct Script {
        interactive: bool,
        answers: VecDeque<String>,
        questions: Vec<String>,
        defaults: Vec<Option<String>>,
        /// What `--password-stdin` reads.
        stdin: Option<String>,
    }

    impl Script {
        fn offline() -> Self {
            Self::default()
        }

        fn answering(answers: &[&str]) -> Self {
            Self {
                interactive: true,
                answers: answers.iter().map(|a| a.to_string()).collect(),
                ..Self::default()
            }
        }

        fn with_stdin(password: &str) -> Self {
            Self {
                stdin: Some(password.to_string()),
                ..Self::default()
            }
        }

        fn next(&mut self, question: &str) -> Result<String, CliError> {
            self.questions.push(question.to_string());
            self.answers
                .pop_front()
                .ok_or_else(|| CliError::Usage(format!("unscripted question: {question}")))
        }
    }

    impl Prompter for Script {
        fn interactive(&self) -> bool {
            self.interactive
        }
        fn ask(&mut self, question: &str, default: Option<&str>) -> Result<String, CliError> {
            self.defaults.push(default.map(str::to_string));
            self.next(question)
        }
        fn ask_secret(&mut self, question: &str) -> Result<Secret, CliError> {
            self.next(question).map(Secret::new)
        }
        fn read_password_stdin(&mut self) -> Result<Secret, CliError> {
            let bytes = self
                .stdin
                .take()
                .ok_or_else(|| CliError::Usage("no scripted stdin".into()))?
                .into_bytes();
            crate::secret_store::password_from_stdin(bytes)
                .map_err(|e| CliError::Usage(e.to_string()))
        }
        fn confirm(&mut self, question: &str) -> Result<bool, CliError> {
            Ok(self.next(question)? == "y")
        }
    }

    /// Accepts every account unless its username is in `reject`; records
    /// `name|username|password-matches-FAKE` per call.
    #[derive(Debug, Default)]
    struct FakeVerifier {
        reject: Vec<String>,
        reject_all: bool,
        calls: RefCell<Vec<String>>,
    }

    impl FakeVerifier {
        fn rejecting() -> Self {
            Self {
                reject_all: true,
                ..Self::default()
            }
        }
        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
    }

    impl Verifier for FakeVerifier {
        async fn verify(&self, account: &AccountConfig, password: &Secret) -> Result<(), AppError> {
            self.calls.borrow_mut().push(format!(
                "{}|{}|{}",
                account.name,
                account.username,
                password.expose() == FAKE
            ));
            if self.reject_all || self.reject.contains(&account.username) {
                Err(AppError::JmapConnection("401 Unauthorized".into()))
            } else {
                Ok(())
            }
        }
    }

    fn command_flags() -> Vec<String> {
        [
            "--password-command",
            "/bin/sh",
            "--password-command",
            "-c",
            "--password-command",
        ]
        .map(String::from)
        .into_iter()
        .chain([format!("printf %s {FAKE}")])
        .collect()
    }

    fn add_flags(name: &str) -> Vec<String> {
        let mut flags: Vec<String> = [
            "add",
            "--name",
            name,
            "--url",
            "https://mail.example.com",
            "--username",
        ]
        .map(String::from)
        .to_vec();
        flags.push(format!("{name}@example.com"));
        flags.extend(command_flags());
        flags.push("--yes".into());
        flags
    }

    /// Runs with no password stores, so the tests do not depend on the
    /// machine (`op` installed, macOS or not).
    async fn run_with(
        args: &[String],
        path: &Path,
        prompter: &mut Script,
        verifier: &FakeVerifier,
    ) -> (Result<bool, CliError>, String) {
        run_in(args, path, prompter, verifier, &SecretStores::default()).await
    }

    async fn run_in(
        args: &[String],
        path: &Path,
        prompter: &mut Script,
        verifier: &FakeVerifier,
        stores: &SecretStores,
    ) -> (Result<bool, CliError>, String) {
        let argv = ["stalwart-mcp", "account"]
            .into_iter()
            .map(String::from)
            .chain(args.iter().cloned());
        let action = match Cli::try_parse_from(argv).expect("parses").command {
            Commands::Account { action } => action,
            other => panic!("{other:?}"),
        };
        let mut out = Vec::new();
        let result = run_with_stores(action, path, prompter, verifier, stores, &mut out).await;
        (result, String::from_utf8(out).expect("utf8"))
    }

    async fn run_ok(args: &[&str], path: &Path, verifier: &FakeVerifier) -> String {
        let args: Vec<String> = args.iter().map(|a| a.to_string()).collect();
        let (result, out) = run_with(&args, path, &mut Script::offline(), verifier).await;
        assert!(result.expect("command succeeds"), "{out}");
        out
    }

    fn temp_config() -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("stalwart-mcp").join("config.toml");
        (dir, path)
    }

    /// A config with two command-source accounts, `a` (default) and `b`.
    async fn two_accounts() -> (tempfile::TempDir, PathBuf, FakeVerifier) {
        let (dir, path) = temp_config();
        let verifier = FakeVerifier::default();
        for name in ["a", "b"] {
            let (result, out) =
                run_with(&add_flags(name), &path, &mut Script::offline(), &verifier).await;
            assert!(result.expect("add"), "{out}");
        }
        (dir, path, verifier)
    }

    #[tokio::test]
    async fn add_into_an_empty_dir_creates_a_loadable_config() {
        let (_dir, path) = temp_config();
        let verifier = FakeVerifier::default();
        let (result, out) =
            run_with(&add_flags("work"), &path, &mut Script::offline(), &verifier).await;
        assert!(result.expect("add"), "{out}");
        assert!(out.contains("Added account 'work' (command sh)"), "{out}");
        assert!(out.contains("'work' is the default account"), "{out}");
        assert!(!out.contains(FAKE), "{out}");
        assert_eq!(verifier.calls(), ["work|work@example.com|true"]);

        let config = AppConfig::load(Some(&path)).expect("loadable");
        assert_eq!(config.default_account.as_deref(), Some("work"));
        let argv = config.accounts[0]
            .password_command
            .clone()
            .expect("command");
        assert_eq!(argv[0], "/bin/sh");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o600);
        }

        // A second account does not take over the default unless --default.
        let (result, _) = run_with(
            &add_flags("other"),
            &path,
            &mut Script::offline(),
            &verifier,
        )
        .await;
        assert!(result.expect("add other"));
        let config = AppConfig::load(Some(&path)).expect("load");
        assert_eq!(config.default_account.as_deref(), Some("work"));
        let mut flags = add_flags("third");
        flags.push("--default".into());
        let (result, _) = run_with(&flags, &path, &mut Script::offline(), &verifier).await;
        assert!(result.expect("add third"));
        let config = AppConfig::load(Some(&path)).expect("load");
        assert_eq!(config.default_account.as_deref(), Some("third"));

        // The name is taken now.
        let (result, _) =
            run_with(&add_flags("work"), &path, &mut Script::offline(), &verifier).await;
        assert!(
            result
                .expect_err("duplicate")
                .to_string()
                .contains("already exists")
        );
    }

    #[tokio::test]
    async fn add_with_a_failing_check_writes_nothing() {
        let (_dir, path) = temp_config();
        let verifier = FakeVerifier::rejecting();
        let (result, out) =
            run_with(&add_flags("work"), &path, &mut Script::offline(), &verifier).await;
        let err = result.expect_err("rejected").to_string();
        assert!(
            err.contains("credential check failed") && err.contains("401"),
            "{err}"
        );
        assert!(!err.contains(FAKE) && !out.contains(FAKE), "{err} {out}");
        assert!(!path.exists());
        assert!(!path.parent().expect("dir").exists());

        // A failing password command also writes nothing.
        let flags: Vec<String> = [
            "add",
            "--name",
            "work",
            "--url",
            "https://mail.example.com",
            "--username",
            "u@example.com",
            "--password-command",
            "/bin/sh",
            "--password-command",
            "-c",
            "--password-command",
        ]
        .map(String::from)
        .into_iter()
        .chain([
            format!("printf %s {FAKE}; echo denied >&2; exit 4"),
            "--yes".into(),
        ])
        .collect();
        let (result, _) = run_with(&flags, &path, &mut Script::offline(), &verifier).await;
        let err = result.expect_err("command fails").to_string();
        assert!(err.contains("denied") && !err.contains(FAKE), "{err}");
        assert!(!path.exists());
    }

    #[tokio::test]
    async fn no_verify_writes_without_checking() {
        let (_dir, path) = temp_config();
        let verifier = FakeVerifier::rejecting();
        let out = run_ok(
            &[
                "add",
                "--name",
                "work",
                "--url",
                "https://mail.example.com",
                "--username",
                "u@example.com",
                "--password-env",
                "STALWART_MCP_TEST_UNSET_VARIABLE",
                "--no-verify",
                "--yes",
            ],
            &path,
            &verifier,
        )
        .await;
        assert!(out.contains("--no-verify"), "{out}");
        assert!(verifier.calls().is_empty());
        let config = AppConfig::load(Some(&path)).expect("load");
        assert_eq!(
            config.accounts[0].password_env.as_deref(),
            Some("STALWART_MCP_TEST_UNSET_VARIABLE")
        );

        // Without --no-verify an unset variable is an error and nothing changes.
        let before = std::fs::read_to_string(&path).expect("read");
        let args: Vec<String> = [
            "add",
            "--name",
            "two",
            "--url",
            "https://mail.example.com",
            "--username",
            "u@example.com",
            "--password-env",
            "STALWART_MCP_TEST_UNSET_VARIABLE",
            "--yes",
        ]
        .map(String::from)
        .to_vec();
        let (result, _) = run_with(&args, &path, &mut Script::offline(), &verifier).await;
        assert!(result.expect_err("unset").to_string().contains("not set"));
        assert_eq!(std::fs::read_to_string(&path).expect("read"), before);
    }

    #[tokio::test]
    async fn non_interactive_missing_values_name_the_flag() {
        let (_dir, path) = temp_config();
        let verifier = FakeVerifier::default();
        let full = add_flags("work");
        let without = |flag: &str, with_value: bool| -> Vec<String> {
            let mut out = Vec::new();
            let mut skip = false;
            for arg in &full {
                if skip {
                    skip = false;
                    continue;
                }
                if arg == flag {
                    skip = with_value;
                    continue;
                }
                out.push(arg.clone());
            }
            out
        };
        for (flag, args) in [
            ("--name", without("--name", true)),
            ("--url", without("--url", true)),
            ("--username", without("--username", true)),
            ("--password-source", without("--password-command", true)),
            ("--yes", without("--yes", false)),
        ] {
            let (result, _) = run_with(&args, &path, &mut Script::offline(), &verifier).await;
            let err = result.expect_err("missing").to_string();
            assert!(
                err.contains(flag) && err.contains("no terminal"),
                "{flag}: {err}"
            );
            assert!(!path.exists(), "{flag}");
        }
        let args: Vec<String> = ["add", "--password-source", "env"]
            .map(String::from)
            .to_vec();
        let (result, _) = run_with(&args, &path, &mut Script::offline(), &verifier).await;
        assert!(result.expect_err("missing").to_string().contains("--name"));
    }

    #[tokio::test]
    async fn interactive_add_asks_for_missing_values() {
        let (_dir, path) = temp_config();
        let verifier = FakeVerifier::default();
        let mut script = Script::answering(&[
            "work",
            "https://mail.example.com",
            "u@example.com",
            "env",
            "HOME",
            "y",
        ]);
        let (result, out) = run_with(&["add".to_string()], &path, &mut script, &verifier).await;
        assert!(result.expect("add"), "{out}");
        assert_eq!(script.questions.len(), 6, "{:?}", script.questions);
        assert!(script.questions.iter().all(|q| !q.contains(FAKE)));
        let config = AppConfig::load(Some(&path)).expect("load");
        assert_eq!(config.accounts[0].password_env.as_deref(), Some("HOME"));
        assert_eq!(verifier.calls(), ["work|u@example.com|false"]);

        // Declining the confirmation writes nothing.
        let mut script = Script::answering(&[
            "two",
            "https://mail.example.com",
            "u@example.com",
            "env",
            "HOME",
            "n",
        ]);
        let before = std::fs::read_to_string(&path).expect("read");
        let (result, _) = run_with(&["add".to_string()], &path, &mut script, &verifier).await;
        assert!(matches!(result, Err(CliError::Aborted)));
        assert_eq!(std::fs::read_to_string(&path).expect("read"), before);
    }

    #[tokio::test]
    async fn store_sources_without_their_programs_are_refused() {
        let (_dir, path) = temp_config();
        let verifier = FakeVerifier::default();
        let base = [
            "add",
            "--name",
            "work",
            "--url",
            "https://mail.example.com",
            "--username",
            "u@example.com",
            "--yes",
        ];
        // No stores at all: neither `op` nor the Keychain.
        for (extra, expected) in [
            (
                &["--password-source", "1password"][..],
                "(op) was not found",
            ),
            (
                &["--password-source", "keychain"],
                "only available on macOS",
            ),
            (
                &["--op-reference", "op://vault/item/password"],
                "(op) was not found",
            ),
            (&["--op-vault", "Private"], "(op) was not found"),
            (
                &["--password-stdin"],
                "--password-source 1password or keychain",
            ),
            (
                &["--password-source", "keychain", "--password-stdin"],
                "only available on macOS",
            ),
        ] {
            let args: Vec<String> = base.iter().chain(extra).map(|a| a.to_string()).collect();
            let (result, _) = run_with(&args, &path, &mut Script::offline(), &verifier).await;
            let err = result.expect_err("refused").to_string();
            assert!(err.contains(expected), "{extra:?}: {err}");
        }
        // Mismatched source flags are usage errors.
        for extra in [
            &["--password-source", "env", "--password-command", "/bin/sh"][..],
            &["--password-source", "command", "--password-env", "X"],
            &["--password-source", "env", "--password-stdin"],
            &["--password-env", "X", "--force"],
            &[
                "--password-source",
                "keychain",
                "--keychain-service",
                "other",
            ],
        ] {
            let args: Vec<String> = base.iter().chain(extra).map(|a| a.to_string()).collect();
            let (result, _) = run_with(&args, &path, &mut Script::offline(), &verifier).await;
            assert!(matches!(result, Err(CliError::Usage(_))), "{extra:?}");
        }
        assert!(!path.exists());
        assert!(verifier.calls().is_empty());
    }

    #[tokio::test]
    async fn list_shows_sources_and_never_a_secret() {
        let (_dir, path) = temp_config();
        let verifier = FakeVerifier::default();
        run_ok(
            &add_flags("cmd")
                .iter()
                .map(String::as_str)
                .collect::<Vec<_>>(),
            &path,
            &verifier,
        )
        .await;
        let mut doc = ConfigDocument::load_or_new(&path).expect("load");
        let entries = [
            ("envy", PasswordSetting::Env("MY_PASSWORD".into())),
            ("plain", PasswordSetting::DefaultEnv),
            (
                "onepw",
                PasswordSetting::Command(
                    [
                        "/opt/homebrew/bin/op",
                        "read",
                        "-n",
                        "--account",
                        "ACC",
                        "op://v/i/password",
                    ]
                    .map(String::from)
                    .to_vec(),
                ),
            ),
            (
                "chain",
                PasswordSetting::Command(
                    [
                        "/usr/bin/security",
                        "find-generic-password",
                        "-s",
                        "stalwart-mcp",
                        "-a",
                        "chain",
                        "-w",
                    ]
                    .map(String::from)
                    .to_vec(),
                ),
            ),
        ];
        for (name, password) in entries {
            doc.add_account(&AccountEntry {
                name: name.into(),
                url: "https://mail.example.com".into(),
                username: format!("{name}@example.com"),
                password,
            })
            .expect("add");
        }
        doc.save().expect("save");

        let text = run_ok(&["list"], &path, &verifier).await;
        for expected in [
            "command sh",
            "env MY_PASSWORD",
            "env STALWART_PASSWORD",
            "1password",
            "keychain",
            "* cmd",
        ] {
            assert!(text.contains(expected), "{expected}: {text}");
        }
        for hidden in [FAKE, "printf", "op://", "find-generic-password", "ACC"] {
            assert!(!text.contains(hidden), "{hidden}: {text}");
        }

        let json = run_ok(&["list", "--json"], &path, &verifier).await;
        for hidden in [FAKE, "printf", "op://", "find-generic-password", "\"-c\""] {
            assert!(!json.contains(hidden), "{hidden}: {json}");
        }
        let value: serde_json::Value = serde_json::from_str(&json).expect("json");
        assert_eq!(value["default_account"], "cmd");
        let accounts = value["accounts"].as_array().expect("accounts");
        let kinds: Vec<_> = accounts
            .iter()
            .map(|a| a["password_source"]["kind"].as_str().expect("kind"))
            .collect();
        assert_eq!(kinds, ["command", "env", "env", "1password", "keychain"]);
        assert_eq!(accounts[0]["password_source"]["program"], "sh");
        assert_eq!(accounts[0]["default"], true);
        assert_eq!(accounts[1]["password_source"]["variable"], "MY_PASSWORD");
        assert_eq!(accounts[1]["default"], false);
        assert_eq!(accounts[1]["username"], "envy@example.com");

        // An empty or missing config lists nothing and is not an error.
        let (_d, empty) = temp_config();
        assert!(
            run_ok(&["list"], &empty, &verifier)
                .await
                .contains("No accounts")
        );
        let json = run_ok(&["list", "--json"], &empty, &verifier).await;
        let value: serde_json::Value = serde_json::from_str(&json).expect("json");
        assert_eq!(value["accounts"], serde_json::json!([]));
        assert!(!empty.exists());
    }

    #[tokio::test]
    async fn edit_rename_keeps_the_default() {
        let (_dir, path, verifier) = two_accounts().await;
        let calls = verifier.calls().len();
        let out = run_ok(
            &["edit", "a", "--rename", "main", "--yes"],
            &path,
            &verifier,
        )
        .await;
        assert!(out.contains("'main' stays the default account"), "{out}");
        assert_eq!(
            verifier.calls().len(),
            calls,
            "a rename alone does not re-verify"
        );
        let config = AppConfig::load(Some(&path)).expect("load");
        assert_eq!(config.default_account.as_deref(), Some("main"));
        let names: Vec<_> = config.accounts.iter().map(|a| a.name.as_str()).collect();
        assert_eq!(names, ["main", "b"]);

        let args: Vec<String> = ["edit", "main", "--rename", "b", "--yes"]
            .map(String::from)
            .to_vec();
        let (result, _) = run_with(&args, &path, &mut Script::offline(), &verifier).await;
        assert!(
            result
                .expect_err("taken")
                .to_string()
                .contains("already exists")
        );

        let args: Vec<String> = ["edit", "main", "--yes"].map(String::from).to_vec();
        let (result, _) = run_with(&args, &path, &mut Script::offline(), &verifier).await;
        assert!(
            result
                .expect_err("nothing")
                .to_string()
                .contains("nothing to change")
        );

        let args: Vec<String> = ["edit", "missing", "--url", "https://x.example.com", "--yes"]
            .map(String::from)
            .to_vec();
        let (result, _) = run_with(&args, &path, &mut Script::offline(), &verifier).await;
        assert!(
            result
                .expect_err("missing")
                .to_string()
                .contains("no account named")
        );
    }

    #[tokio::test]
    async fn edit_reverifies_when_url_username_or_source_changes() {
        let (_dir, path, verifier) = two_accounts().await;
        let before = std::fs::read_to_string(&path).expect("read");

        let rejecting = FakeVerifier::rejecting();
        let args: Vec<String> = ["edit", "b", "--url", "https://other.example.com", "--yes"]
            .map(String::from)
            .to_vec();
        let (result, _) = run_with(&args, &path, &mut Script::offline(), &rejecting).await;
        assert!(result.is_err());
        assert_eq!(rejecting.calls(), ["b|b@example.com|true"]);
        assert_eq!(std::fs::read_to_string(&path).expect("read"), before);

        let calls = verifier.calls().len();
        let out = run_ok(
            &["edit", "b", "--username", "new@example.com", "--yes"],
            &path,
            &verifier,
        )
        .await;
        assert!(out.contains("Updated account 'b'"), "{out}");
        assert_eq!(verifier.calls()[calls], "b|new@example.com|true");

        let out = run_ok(
            &["edit", "b", "--password-env", "HOME", "--default", "--yes"],
            &path,
            &verifier,
        )
        .await;
        assert!(out.contains("Password source: env HOME"), "{out}");
        assert_eq!(verifier.calls().len(), calls + 2);
        let config = AppConfig::load(Some(&path)).expect("load");
        assert_eq!(config.default_account.as_deref(), Some("b"));
        let b = &config.accounts[1];
        assert_eq!(
            (b.password_env.as_deref(), b.password_command.is_none()),
            (Some("HOME"), true)
        );

        // --no-verify skips the check.
        run_ok(
            &[
                "edit",
                "b",
                "--url",
                "https://x.example.com",
                "--no-verify",
                "--yes",
            ],
            &path,
            &verifier,
        )
        .await;
        assert_eq!(verifier.calls().len(), calls + 2);
    }

    #[tokio::test]
    async fn remove_of_the_default_moves_it() {
        let (_dir, path, verifier) = two_accounts().await;
        let args: Vec<String> = ["remove", "a"].map(String::from).to_vec();
        let (result, _) = run_with(&args, &path, &mut Script::offline(), &verifier).await;
        assert!(
            result
                .expect_err("needs --yes")
                .to_string()
                .contains("--yes")
        );

        // --delete-secret on a command account is refused before anything changes.
        let args: Vec<String> = ["remove", "a", "--yes", "--delete-secret"]
            .map(String::from)
            .to_vec();
        let (result, _) = run_with(&args, &path, &mut Script::offline(), &verifier).await;
        assert!(
            result
                .expect_err("no secret")
                .to_string()
                .contains("no stored secret")
        );

        let out = run_ok(&["remove", "a", "--yes"], &path, &verifier).await;
        assert!(out.contains("the default is now 'b'"), "{out}");
        let config = AppConfig::load(Some(&path)).expect("load");
        assert_eq!(config.default_account.as_deref(), Some("b"));
        assert_eq!(config.accounts.len(), 1);

        let out = run_ok(&["remove", "b", "--yes"], &path, &verifier).await;
        assert!(out.contains("No accounts remain"), "{out}");
        let config = AppConfig::load_allow_empty(Some(&path)).expect("load");
        assert!(config.accounts.is_empty() && config.default_account.is_none());

        let args: Vec<String> = ["remove", "b", "--yes"].map(String::from).to_vec();
        let (result, _) = run_with(&args, &path, &mut Script::offline(), &verifier).await;
        assert!(
            result
                .expect_err("gone")
                .to_string()
                .contains("no account named")
        );
    }

    #[tokio::test]
    async fn remove_delete_secret_needs_the_exact_keychain_shape() {
        let (_dir, path) = temp_config();
        let mut doc = ConfigDocument::load_or_new(&path).expect("new");
        doc.add_account(&AccountEntry {
            name: "k".into(),
            url: "https://mail.example.com".into(),
            username: "k@example.com".into(),
            password: PasswordSetting::Command(
                ["/usr/bin/security", "find-generic-password", "-w"]
                    .map(String::from)
                    .to_vec(),
            ),
        })
        .expect("add");
        doc.save().expect("save");
        let args: Vec<String> = ["remove", "k", "--yes", "--delete-secret"]
            .map(String::from)
            .to_vec();
        // Without a Keychain on this "system".
        let (result, _) = run_with(
            &args,
            &path,
            &mut Script::offline(),
            &FakeVerifier::default(),
        )
        .await;
        let err = result.expect_err("refused").to_string();
        assert!(err.contains("not available on this system"), "{err}");
        // With one, the argv is not the exact shape.
        let stores = SecretStores {
            op: None,
            keychain: Some(Keychain::new(
                crate::secret_store::SECURITY_PROGRAM,
                KEYCHAIN_SERVICE,
            )),
        };
        let (result, _) = run_in(
            &args,
            &path,
            &mut Script::offline(),
            &FakeVerifier::default(),
            &stores,
        )
        .await;
        let err = result.expect_err("refused").to_string();
        assert!(err.contains("not exactly the Keychain command"), "{err}");
        assert_eq!(
            ConfigDocument::load_or_new(&path)
                .expect("load")
                .accounts()
                .expect("accounts")
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn test_reports_per_account_and_fails_when_any_fails() {
        let (_dir, path, _) = two_accounts().await;
        let verifier = FakeVerifier {
            reject: vec!["b@example.com".into()],
            ..FakeVerifier::default()
        };
        let args = vec!["test".to_string()];
        let (result, out) = run_with(&args, &path, &mut Script::offline(), &verifier).await;
        assert!(!result.expect("runs"), "{out}");
        assert!(out.contains("a: ok"), "{out}");
        assert!(out.contains("b: ") && out.contains("401"), "{out}");
        assert!(!out.contains(FAKE), "{out}");
        assert_eq!(
            verifier.calls(),
            ["a|a@example.com|true", "b|b@example.com|true"]
        );

        let out = run_ok(&["test", "a"], &path, &verifier).await;
        assert_eq!(out.trim(), "a: ok");

        let args = vec!["test".to_string(), "nope".to_string()];
        let (result, _) = run_with(&args, &path, &mut Script::offline(), &verifier).await;
        assert!(
            result
                .expect_err("unknown")
                .to_string()
                .contains("no account named")
        );

        let (_d, empty) = temp_config();
        let (result, _) =
            run_with(&["test".into()], &empty, &mut Script::offline(), &verifier).await;
        assert!(
            result
                .expect_err("empty")
                .to_string()
                .contains("no accounts")
        );
    }

    #[tokio::test]
    async fn invalid_names_are_refused() {
        let (_dir, path) = temp_config();
        let verifier = FakeVerifier::default();
        let long = "x".repeat(65);
        for bad in ["bad name", "", "a/b", "über", long.as_str(), "a.b"] {
            let mut flags = add_flags("placeholder");
            flags[2] = bad.to_string();
            let (result, _) = run_with(&flags, &path, &mut Script::offline(), &verifier).await;
            let err = result.expect_err("refused").to_string();
            assert!(err.contains("invalid account name"), "{bad}: {err}");
        }
        assert!(!path.exists());
        assert!(verifier.calls().is_empty());

        let ok = "A-b_9".to_string() + &"z".repeat(59);
        assert!(validate_account_name(&ok).is_ok());
        let (result, _) = run_with(&add_flags(&ok), &path, &mut Script::offline(), &verifier).await;
        assert!(result.expect("64 chars ok"));
        let args: Vec<String> = ["edit", ok.as_str(), "--rename", "x y", "--yes"]
            .map(String::from)
            .to_vec();
        let (result, _) = run_with(&args, &path, &mut Script::offline(), &verifier).await;
        assert!(
            result
                .expect_err("rename")
                .to_string()
                .contains("invalid account name")
        );
    }

    #[tokio::test]
    async fn bad_url_and_env_names_are_refused() {
        let (_dir, path) = temp_config();
        let verifier = FakeVerifier::default();
        for url in ["mail.example.com", "ftp://mail.example.com", "https://"] {
            let mut flags = add_flags("work");
            flags[4] = url.to_string();
            let (result, _) = run_with(&flags, &path, &mut Script::offline(), &verifier).await;
            assert!(
                result.expect_err("url").to_string().contains("--url"),
                "{url}"
            );
        }
        for var in ["1X", "A-B", "A B"] {
            let args: Vec<String> = [
                "add",
                "--name",
                "w",
                "--url",
                "https://mail.example.com",
                "--username",
                "u",
                "--password-env",
                var,
                "--yes",
            ]
            .map(String::from)
            .to_vec();
            let (result, _) = run_with(&args, &path, &mut Script::offline(), &verifier).await;
            assert!(
                result
                    .expect_err("var")
                    .to_string()
                    .contains("--password-env"),
                "{var}"
            );
        }
        assert!(!path.exists());
    }

    #[test]
    fn resolve_program_uses_absolute_path_entries_only() {
        let dir = tempfile::tempdir().expect("tempdir");
        let path_var = std::ffi::OsString::from(format!(
            "relative/bin:{}:/bin:/usr/bin",
            dir.path().join("missing").display()
        ));
        let cwd = Path::new("/");
        assert_eq!(
            resolve_program("sh", Some(&path_var), cwd).expect("sh"),
            "/bin/sh"
        );
        assert_eq!(
            resolve_program("/bin/sh", None, cwd).expect("absolute"),
            "/bin/sh"
        );
        assert_eq!(
            resolve_program("bin/sh", None, cwd).expect("relative to cwd"),
            "/bin/sh"
        );
        let err = resolve_program("stalwart-mcp-no-such-program", Some(&path_var), cwd)
            .expect_err("missing")
            .to_string();
        assert!(err.contains("not found on PATH"), "{err}");
        assert!(resolve_program("sh", None, cwd).is_err());
        assert!(resolve_program("", Some(&path_var), cwd).is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let plain = dir.path().join("plain");
            std::fs::write(&plain, "").expect("write");
            std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o644))
                .expect("chmod");
            let err = resolve_program(plain.to_str().expect("utf8"), None, cwd)
                .expect_err("not executable")
                .to_string();
            assert!(err.contains("not an executable file"), "{err}");
            let only_dir = std::ffi::OsString::from(dir.path());
            assert!(resolve_program("plain", Some(&only_dir), cwd).is_err());
        }
    }

    #[test]
    fn source_description_recognises_store_shapes() {
        let cmd = |argv: &[&str]| {
            SourceDescription::of(&PasswordSetting::Command(
                argv.iter().map(|a| a.to_string()).collect(),
            ))
        };
        assert_eq!(
            cmd(&["/usr/local/bin/op", "read", "-n", "op://x"]),
            SourceDescription::OnePassword
        );
        assert_eq!(
            cmd(&["/usr/bin/security", "find-generic-password", "-w"]),
            SourceDescription::Keychain
        );
        assert_eq!(
            cmd(&["/usr/bin/security", "dump-keychain"]),
            SourceDescription::Command("security".into())
        );
        assert_eq!(
            cmd(&["/opt/pw/bin/pass", "show", "mail"]).to_string(),
            "command pass"
        );
        assert_eq!(
            SourceDescription::of(&PasswordSetting::DefaultEnv).to_string(),
            "env STALWART_PASSWORD"
        );
    }

    /// The 1Password and Keychain sources against fake `op` and `security`
    /// scripts that record their argv and stdin.
    #[cfg(unix)]
    mod stores {
        use super::*;
        use std::os::unix::fs::PermissionsExt;

        const FAKE_SECURITY: &str = r#"#!/bin/sh
d=$(dirname "$0")
[ -n "$FAKE_PROBE" ] && exit 0
printf '%s\n' "$*" >> "$d/security.argv"
case "$1" in
  -i)
    line=$(cat)
    printf '%s\n' "$line" >> "$d/security.stdin"
    if [ -f "$d/security-fail-add" ]; then echo "add failed" >&2; exit 45; fi
    acct=$(printf '%s\n' "$line" | sed -n 's/.* -a "\([^"]*\)".*/\1/p')
    : > "$d/item.$acct"
    ;;
  find-generic-password)
    if [ ! -f "$d/item.$5" ]; then echo "security: The specified item could not be found in the keychain." >&2; exit 44; fi
    if [ "$6" = "-w" ]; then cat "$d/readback"; fi
    ;;
  delete-generic-password)
    if [ -f "$d/security-fail-delete" ]; then echo "delete failed" >&2; exit 1; fi
    if [ ! -f "$d/item.$5" ]; then exit 44; fi
    rm "$d/item.$5"
    ;;
  *) echo "unexpected $1" >&2; exit 2 ;;
esac
"#;

        const FAKE_OP: &str = r#"#!/bin/sh
d=$(dirname "$0")
[ -n "$FAKE_PROBE" ] && exit 0
printf '%s\n' "$*" >> "$d/op.argv"
case "$1 $2" in
  "account list") cat "$d/op.accounts" ;;
  "item list") cat "$d/op.items" ;;
  "item get") cat "$d/op.item" ;;
  "item create")
    cat >> "$d/op.stdin"
    if [ -f "$d/op-fail-create" ]; then echo "[ERROR] create failed" >&2; exit 1; fi
    cat "$d/op.created"
    ;;
  "item delete")
    if [ -f "$d/op-fail-delete" ]; then echo "[ERROR] delete failed" >&2; exit 1; fi
    ;;
  "read -n") cat "$d/readback" ;;
  *) echo "unexpected: $*" >&2; exit 2 ;;
esac
"#;

        const ITEM: &str = r#"{"id":"itemid1","title":"Mail work","vault":{"id":"vaultid1","name":"Private"},
            "fields":[{"id":"username","label":"username"},{"id":"password","label":"password","purpose":"PASSWORD"}]}"#;

        struct Fakes {
            dir: tempfile::TempDir,
        }

        impl Fakes {
            fn new() -> Self {
                let fakes = Self {
                    dir: tempfile::tempdir().expect("tempdir"),
                };
                for (name, body) in [("security", FAKE_SECURITY), ("op", FAKE_OP)] {
                    let path = fakes.path(name);
                    std::fs::write(&path, body).expect("write fake");
                    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700))
                        .expect("chmod");
                }
                fakes.write(
                    "op.accounts",
                    r#"[{"url":"my.1password.com","email":"me@example.com","user_uuid":"USERUUID1","account_uuid":"ACCOUNTUUID1"}]"#,
                );
                fakes.write(
                    "op.items",
                    r#"[{"id":"otheritem","title":"Other","vault":{"id":"vaultid1","name":"Private"},"urls":[{"href":"https://other.org"}]},
                        {"id":"urlitem","title":"Mail","vault":{"id":"vaultid1","name":"Private"},"urls":[{"href":"https://example.com"}]},
                        {"id":"titleitem","title":"mail.example.com login","vault":{"id":"vaultid2","name":"Work"}}]"#,
                );
                fakes.write("op.item", ITEM);
                fakes.write(
                    "op.created",
                    r#"{"id":"newitem1","title":"stalwart-mcp work","vault":{"id":"vaultid1","name":"Private"},"fields":[]}"#,
                );
                fakes.write("readback", FAKE);
                // A freshly written script can be "text file busy" on Linux
                // while a forked test thread still holds the write handle.
                for name in ["security", "op"] {
                    probe(&fakes.path(name));
                }
                fakes
            }

            fn path(&self, name: &str) -> PathBuf {
                self.dir.path().join(name)
            }

            fn program(&self, name: &str) -> String {
                self.path(name).to_string_lossy().into_owned()
            }

            fn write(&self, name: &str, content: &str) {
                std::fs::write(self.path(name), content).expect("write");
            }

            fn read(&self, name: &str) -> String {
                std::fs::read_to_string(self.path(name)).unwrap_or_default()
            }

            fn keychain(&self) -> Keychain {
                Keychain::new(self.program("security"), KEYCHAIN_SERVICE)
            }

            fn stores(&self) -> SecretStores {
                SecretStores {
                    op: Some(OnePassword::new(self.program("op"))),
                    keychain: Some(self.keychain()),
                }
            }

            fn assert_no_secret_in_argv(&self) {
                for log in ["op.argv", "security.argv"] {
                    assert!(!self.read(log).contains(FAKE), "{log}");
                }
            }
        }

        fn probe(program: &Path) {
            for _ in 0..200 {
                match std::process::Command::new(program)
                    .env("FAKE_PROBE", "1")
                    .status()
                {
                    Ok(_) => return,
                    Err(e) if e.kind() == std::io::ErrorKind::ExecutableFileBusy => {
                        std::thread::sleep(std::time::Duration::from_millis(10));
                    }
                    Err(e) => panic!("cannot run {}: {e}", program.display()),
                }
            }
            panic!("{} stays busy", program.display());
        }

        fn add_args(name: &str, extra: &[&str]) -> Vec<String> {
            [
                "add",
                "--name",
                name,
                "--url",
                "https://mail.example.com",
                "--username",
                "u@example.com",
                "--yes",
            ]
            .iter()
            .chain(extra)
            .map(|a| a.to_string())
            .collect()
        }

        const KEYCHAIN_STDIN: [&str; 3] = ["--password-source", "keychain", "--password-stdin"];

        fn stdin_script() -> Script {
            Script::with_stdin(&format!("{FAKE}\n"))
        }

        fn account_count(path: &Path) -> usize {
            AppConfig::load_allow_empty(Some(&path.to_path_buf()))
                .map(|c| c.accounts.len())
                .unwrap_or(0)
        }

        #[tokio::test]
        async fn keychain_add_sends_the_password_on_stdin_only() {
            let f = Fakes::new();
            let (_d, path) = temp_config();
            let verifier = FakeVerifier::default();
            let (result, out) = run_in(
                &add_args("work", &KEYCHAIN_STDIN),
                &path,
                &mut stdin_script(),
                &verifier,
                &f.stores(),
            )
            .await;
            assert!(result.expect("add"), "{out}");
            assert!(out.contains("(keychain)") && !out.contains(FAKE), "{out}");
            assert_eq!(verifier.calls(), ["work|u@example.com|true"]);

            let stdin = f.read("security.stdin");
            assert!(
                stdin.contains(&format!(
                    r#"add-generic-password -s "stalwart-mcp" -a "work" -w "{FAKE}""#
                )),
                "{stdin}"
            );
            assert!(!stdin.contains(" -U") && !stdin.contains("-A"), "{stdin}");
            assert!(f.read("security.argv").lines().any(|l| l == "-i"));
            f.assert_no_secret_in_argv();

            let config = AppConfig::load(Some(&path)).expect("load");
            assert_eq!(
                config.accounts[0].password_command.clone().expect("argv"),
                f.keychain().password_command("work")
            );
            assert!(f.path("item.work").exists());
        }

        #[tokio::test]
        async fn keychain_existing_item_needs_force() {
            let f = Fakes::new();
            let (_d, path) = temp_config();
            let verifier = FakeVerifier::default();
            f.write("item.work", "");
            let (result, _) = run_in(
                &add_args("work", &KEYCHAIN_STDIN),
                &path,
                &mut stdin_script(),
                &verifier,
                &f.stores(),
            )
            .await;
            let err = result.expect_err("exists").to_string();
            assert!(
                err.contains("already exists") && err.contains("--force"),
                "{err}"
            );
            assert!(!path.exists());
            assert!(f.read("security.stdin").is_empty());
            assert!(verifier.calls().is_empty(), "refused before the check");

            let mut args = add_args("work", &KEYCHAIN_STDIN);
            args.push("--force".into());
            let (result, out) =
                run_in(&args, &path, &mut stdin_script(), &verifier, &f.stores()).await;
            assert!(result.expect("forced"), "{out}");
            assert!(f.read("security.stdin").contains(" -U -w "));
            f.assert_no_secret_in_argv();

            // --force never overwrites an item another account reads.
            let mut doc = ConfigDocument::load_or_new(&path).expect("load");
            doc.add_account(&AccountEntry {
                name: "other".into(),
                url: "https://mail.example.com".into(),
                username: "o@example.com".into(),
                password: PasswordSetting::Command(f.keychain().password_command("shared")),
            })
            .expect("add");
            doc.save().expect("save");
            let mut args = add_args("shared", &KEYCHAIN_STDIN);
            args.push("--force".into());
            let (result, _) =
                run_in(&args, &path, &mut stdin_script(), &verifier, &f.stores()).await;
            let err = result.expect_err("in use").to_string();
            assert!(err.contains("password source of account 'other'"), "{err}");
        }

        #[tokio::test]
        async fn keychain_failing_final_check_rolls_back() {
            let f = Fakes::new();
            let (_d, path) = temp_config();
            let verifier = FakeVerifier::default();
            f.write("readback", "something-else");
            let (result, out) = run_in(
                &add_args("work", &KEYCHAIN_STDIN),
                &path,
                &mut stdin_script(),
                &verifier,
                &f.stores(),
            )
            .await;
            let err = result.expect_err("final check").to_string();
            assert!(err.contains("final check"), "{err}");
            assert!(err.contains("removed again"), "{err}");
            assert!(!err.contains(FAKE) && !out.contains(FAKE), "{err}");
            assert!(!f.path("item.work").exists());
            assert!(
                f.read("security.argv")
                    .lines()
                    .any(|l| l == "delete-generic-password -s stalwart-mcp -a work")
            );
            assert_eq!(account_count(&path), 0);

            // A failing rollback names the item to remove by hand.
            f.write("security-fail-delete", "");
            let (_d2, path2) = temp_config();
            let (result, _) = run_in(
                &add_args("work", &KEYCHAIN_STDIN),
                &path2,
                &mut stdin_script(),
                &verifier,
                &f.stores(),
            )
            .await;
            let err = result.expect_err("final check").to_string();
            assert!(
                err.contains("service 'stalwart-mcp', account 'work'") && err.contains("by hand"),
                "{err}"
            );
            assert!(err.contains("security delete-generic-password"), "{err}");
            assert_eq!(account_count(&path2), 0);
        }

        #[tokio::test]
        async fn keychain_refuses_line_breaks() {
            let f = Fakes::new();
            let (_d, path) = temp_config();
            let verifier = FakeVerifier::default();
            for typed in ["a\rb", "a\nb"] {
                let (result, _) = run_in(
                    &add_args("work", &KEYCHAIN_STDIN),
                    &path,
                    &mut Script::with_stdin(typed),
                    &verifier,
                    &f.stores(),
                )
                .await;
                let err = result.expect_err("refused").to_string();
                assert!(err.contains("line break"), "{err}");
            }
            // Typed on the terminal, too.
            let mut script = Script::answering(&["x\ny"]);
            let (result, _) = run_in(
                &add_args("work", &["--password-source", "keychain"]),
                &path,
                &mut script,
                &verifier,
                &f.stores(),
            )
            .await;
            assert!(
                result
                    .expect_err("refused")
                    .to_string()
                    .contains("line break")
            );
            assert!(f.read("security.argv").is_empty());
            assert!(!path.exists());
        }

        #[tokio::test]
        async fn remove_deletes_only_the_item_named_by_the_argv() {
            let f = Fakes::new();
            let (_d, path) = temp_config();
            let verifier = FakeVerifier::default();
            for name in ["work", "keep"] {
                let (result, out) = run_in(
                    &add_args(name, &KEYCHAIN_STDIN),
                    &path,
                    &mut stdin_script(),
                    &verifier,
                    &f.stores(),
                )
                .await;
                assert!(result.expect("add"), "{out}");
            }
            let remove = |args: &[&str]| args.iter().map(|a| a.to_string()).collect::<Vec<_>>();

            let (result, out) = run_in(
                &remove(&["remove", "work", "--yes", "--delete-secret"]),
                &path,
                &mut Script::offline(),
                &verifier,
                &f.stores(),
            )
            .await;
            assert!(result.expect("remove"), "{out}");
            assert!(out.contains("Deleted the Keychain item"), "{out}");
            assert!(!f.path("item.work").exists());
            assert!(f.path("item.keep").exists());
            let deletes: Vec<String> = f
                .read("security.argv")
                .lines()
                .filter(|l| l.starts_with("delete-generic-password"))
                .map(str::to_string)
                .collect();
            assert_eq!(deletes, ["delete-generic-password -s stalwart-mcp -a work"]);

            // --yes without --delete-secret keeps the item and says how to delete it.
            let (result, out) = run_in(
                &remove(&["remove", "keep", "--yes"]),
                &path,
                &mut Script::offline(),
                &verifier,
                &f.stores(),
            )
            .await;
            assert!(result.expect("remove"), "{out}");
            assert!(out.contains("Kept the Keychain item"), "{out}");
            assert!(f.path("item.keep").exists());

            // The item comes from the argv's -a, not from the account name; a
            // foreign service is never touched.
            let mut doc = ConfigDocument::load_or_new(&path).expect("load");
            let entry = |name: &str, argv: Vec<String>| AccountEntry {
                name: name.into(),
                url: "https://mail.example.com".into(),
                username: "x@example.com".into(),
                password: PasswordSetting::Command(argv),
            };
            doc.add_account(&entry("byargv", f.keychain().password_command("keep")))
                .expect("add");
            let foreign = Keychain::new(f.program("security"), "someone-else");
            doc.add_account(&entry("foreign", foreign.password_command("foreign")))
                .expect("add");
            doc.save().expect("save");
            f.write("item.foreign", "");

            let (result, _) = run_in(
                &remove(&["remove", "foreign", "--yes", "--delete-secret"]),
                &path,
                &mut Script::offline(),
                &verifier,
                &f.stores(),
            )
            .await;
            let err = result.expect_err("foreign").to_string();
            assert!(err.contains("not exactly the Keychain command"), "{err}");
            assert!(f.path("item.foreign").exists());

            // Interactive: the prompt decides.
            let mut script = Script::answering(&["y", "y"]);
            let (result, out) = run_in(
                &remove(&["remove", "byargv"]),
                &path,
                &mut script,
                &verifier,
                &f.stores(),
            )
            .await;
            assert!(result.expect("remove"), "{out}");
            assert!(
                script.questions[1].contains("account 'keep'"),
                "{:?}",
                script.questions
            );
            assert!(!f.path("item.keep").exists());
            let deletes = f
                .read("security.argv")
                .lines()
                .filter(|l| l.starts_with("delete-generic-password"))
                .count();
            assert_eq!(deletes, 2);
        }

        #[tokio::test]
        async fn remove_never_deletes_an_item_another_account_reads() {
            let f = Fakes::new();
            let (_d, path) = temp_config();
            let verifier = FakeVerifier::default();
            let (result, out) = run_in(
                &add_args("work", &KEYCHAIN_STDIN),
                &path,
                &mut stdin_script(),
                &verifier,
                &f.stores(),
            )
            .await;
            assert!(result.expect("add"), "{out}");
            let mut doc = ConfigDocument::load_or_new(&path).expect("load");
            doc.add_account(&AccountEntry {
                name: "alias".into(),
                url: "https://mail.example.com".into(),
                username: "u@example.com".into(),
                password: PasswordSetting::Command(f.keychain().password_command("work")),
            })
            .expect("add");
            doc.save().expect("save");
            let args = |a: &[&str]| a.iter().map(|s| s.to_string()).collect::<Vec<_>>();

            let (result, _) = run_in(
                &args(&["remove", "work", "--yes", "--delete-secret"]),
                &path,
                &mut Script::offline(),
                &verifier,
                &f.stores(),
            )
            .await;
            let err = result.expect_err("shared").to_string();
            assert!(err.contains("account 'alias'"), "{err}");
            assert!(f.path("item.work").exists());
            assert_eq!(account_count(&path), 2, "nothing removed");

            // Interactive: no "also delete?" question, the item is kept.
            let mut script = Script::answering(&["y"]);
            let (result, out) = run_in(
                &args(&["remove", "work"]),
                &path,
                &mut script,
                &verifier,
                &f.stores(),
            )
            .await;
            assert!(result.expect("remove"), "{out}");
            assert_eq!(script.questions.len(), 1, "{:?}", script.questions);
            assert!(out.contains("account 'alias' still reads it"), "{out}");
            assert!(f.path("item.work").exists());
            assert!(
                !f.read("security.argv")
                    .lines()
                    .any(|l| l.starts_with("delete-generic-password"))
            );
        }

        #[tokio::test]
        async fn a_writable_password_command_directory_is_warned_about() {
            let dir = tempfile::tempdir().expect("tempdir");
            let bin = dir.path().join("bin");
            std::fs::create_dir(&bin).expect("mkdir");
            let program = bin.join("pw");
            std::fs::write(&program, format!("#!/bin/sh\nprintf '%s' '{FAKE}'\n")).expect("write");
            std::fs::set_permissions(&program, std::fs::Permissions::from_mode(0o700))
                .expect("chmod");
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o770)).expect("chmod");
            let program = program.to_string_lossy().into_owned();
            let (_d, path) = temp_config();
            let (result, out) = run_in(
                &add_args("work", &["--password-command", &program, "--no-verify"]),
                &path,
                &mut Script::offline(),
                &FakeVerifier::default(),
                &SecretStores::default(),
            )
            .await;
            std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o700)).expect("chmod");
            assert!(result.expect("added despite the warning"), "{out}");
            let shown = std::fs::canonicalize(&bin).expect("canonical");
            assert!(
                out.contains("warning:")
                    && out.contains(&shown.display().to_string())
                    && out.contains("writable by group or others"),
                "{out}"
            );
            assert_eq!(account_count(&path), 1);
        }

        #[tokio::test]
        async fn rename_moves_the_keychain_item() {
            let f = Fakes::new();
            let (_d, path) = temp_config();
            let verifier = FakeVerifier::default();
            let (result, out) = run_in(
                &add_args("work", &KEYCHAIN_STDIN),
                &path,
                &mut stdin_script(),
                &verifier,
                &f.stores(),
            )
            .await;
            assert!(result.expect("add"), "{out}");

            // A name whose item exists is refused and nothing changes.
            f.write("item.taken", "");
            let before = std::fs::read_to_string(&path).expect("read");
            let args: Vec<String> = ["edit", "work", "--rename", "taken", "--yes"]
                .map(String::from)
                .to_vec();
            let (result, _) =
                run_in(&args, &path, &mut Script::offline(), &verifier, &f.stores()).await;
            assert!(result.expect_err("taken").to_string().contains("--force"));
            assert_eq!(std::fs::read_to_string(&path).expect("read"), before);
            assert!(f.path("item.work").exists());

            let calls = verifier.calls().len();
            let args: Vec<String> = ["edit", "work", "--rename", "main", "--yes"]
                .map(String::from)
                .to_vec();
            let (result, out) =
                run_in(&args, &path, &mut Script::offline(), &verifier, &f.stores()).await;
            assert!(result.expect("rename"), "{out}");
            assert!(out.contains("Moved the Keychain item"), "{out}");
            assert_eq!(verifier.calls().len(), calls, "a rename does not re-verify");
            assert!(f.path("item.main").exists());
            assert!(!f.path("item.work").exists());
            let config = AppConfig::load(Some(&path)).expect("load");
            assert_eq!(config.accounts[0].name, "main");
            assert_eq!(
                config.accounts[0].password_command.clone().expect("argv"),
                f.keychain().password_command("main")
            );
            f.assert_no_secret_in_argv();
        }

        #[tokio::test]
        async fn onepassword_reference_mode_stores_ids() {
            let f = Fakes::new();
            let (_d, path) = temp_config();
            let verifier = FakeVerifier::default();
            let (result, out) = run_in(
                &add_args(
                    "work",
                    &[
                        "--password-source",
                        "1password",
                        "--op-reference",
                        "op://Private/Mail work/password",
                    ],
                ),
                &path,
                &mut Script::offline(),
                &verifier,
                &f.stores(),
            )
            .await;
            assert!(result.expect("add"), "{out}");
            assert!(out.contains("(1password)"), "{out}");
            assert_eq!(verifier.calls(), ["work|u@example.com|true"]);
            let argv = f.read("op.argv");
            assert!(
                argv.lines().any(|l| l == "account list --format json"),
                "{argv}"
            );
            assert!(
                argv.lines().any(|l| l
                    == "item get Mail work --vault Private --account ACCOUNTUUID1 --format json"),
                "{argv}"
            );
            let config = AppConfig::load(Some(&path)).expect("load");
            assert_eq!(
                config.accounts[0].password_command.clone().expect("argv"),
                [
                    f.program("op").as_str(),
                    "read",
                    "-n",
                    "--account",
                    "ACCOUNTUUID1",
                    "op://vaultid1/itemid1/password"
                ]
            );
            f.assert_no_secret_in_argv();
            assert!(f.read("op.stdin").is_empty());

            // Without a reference or a vault and no terminal, the flags are named.
            let (_d2, path2) = temp_config();
            let (result, _) = run_in(
                &add_args("work", &["--password-source", "1password"]),
                &path2,
                &mut Script::offline(),
                &verifier,
                &f.stores(),
            )
            .await;
            let err = result.expect_err("missing").to_string();
            assert!(
                err.contains("--op-reference") && err.contains("--op-vault"),
                "{err}"
            );
        }

        #[tokio::test]
        async fn onepassword_offers_items_matching_the_mail_host() {
            let f = Fakes::new();
            let (_d, path) = temp_config();
            let verifier = FakeVerifier::default();
            f.write(
                "op.item",
                r#"{"id":"titleitem","vault":{"id":"vaultid2","name":"Work"},"fields":[{"id":"password","label":"password"}]}"#,
            );
            let mut script = Script::answering(&["existing", "2", "y"]);
            let (result, out) = run_in(
                &add_args("work", &["--password-source", "1password"])
                    .into_iter()
                    .filter(|a| a != "--yes")
                    .collect::<Vec<_>>(),
                &path,
                &mut script,
                &verifier,
                &f.stores(),
            )
            .await;
            assert!(result.expect("add"), "{out}");
            let list = &script.questions[1];
            assert!(list.contains("1) Mail (vault Private)"), "{list}");
            assert!(
                list.contains("2) mail.example.com login (vault Work)"),
                "{list}"
            );
            assert!(!list.contains("Other"), "{list}");
            assert!(
                f.read("op.argv").lines().any(|l| l
                    == "item get titleitem --vault vaultid2 --account ACCOUNTUUID1 --format json")
            );
            let config = AppConfig::load(Some(&path)).expect("load");
            let argv = config.accounts[0].password_command.clone().expect("argv");
            assert_eq!(argv[5], "op://vaultid2/titleitem/password");
        }

        #[tokio::test]
        async fn onepassword_create_sends_the_template_on_stdin() {
            let f = Fakes::new();
            let (_d, path) = temp_config();
            let verifier = FakeVerifier::default();
            let (result, out) = run_in(
                &add_args("work", &["--op-vault", "Private", "--password-stdin"]),
                &path,
                &mut stdin_script(),
                &verifier,
                &f.stores(),
            )
            .await;
            assert!(result.expect("add"), "{out}");
            let template: serde_json::Value =
                serde_json::from_str(&f.read("op.stdin")).expect("json template");
            assert_eq!(template["title"], "stalwart-mcp work");
            assert_eq!(template["category"], "LOGIN");
            assert_eq!(template["fields"][0]["value"], "u@example.com");
            assert_eq!(template["fields"][1]["id"], "password");
            assert_eq!(template["fields"][1]["type"], "CONCEALED");
            assert_eq!(template["fields"][1]["value"], FAKE);
            assert!(f.read("op.argv").lines().any(|l| l
                == "item create --vault Private --account ACCOUNTUUID1 --url \
                    https://mail.example.com --format json -"));
            f.assert_no_secret_in_argv();
            let config = AppConfig::load(Some(&path)).expect("load");
            let argv = config.accounts[0].password_command.clone().expect("argv");
            assert_eq!(argv[5], "op://vaultid1/newitem1/password");
        }

        #[tokio::test]
        async fn onepassword_create_rolls_back_and_names_the_item_when_that_fails() {
            let f = Fakes::new();
            let verifier = FakeVerifier::default();
            f.write("readback", "something-else");
            let args = add_args("work", &["--op-vault", "Private", "--password-stdin"]);

            let (_d, path) = temp_config();
            let (result, _) =
                run_in(&args, &path, &mut stdin_script(), &verifier, &f.stores()).await;
            let err = result.expect_err("final check").to_string();
            assert!(
                err.contains("final check") && err.contains("removed again"),
                "{err}"
            );
            assert!(
                f.read("op.argv")
                    .lines()
                    .any(|l| l == "item delete newitem1 --vault vaultid1 --account ACCOUNTUUID1")
            );
            assert_eq!(account_count(&path), 0);

            f.write("op-fail-delete", "");
            let (_d2, path2) = temp_config();
            let (result, _) =
                run_in(&args, &path2, &mut stdin_script(), &verifier, &f.stores()).await;
            let err = result.expect_err("final check").to_string();
            assert!(
                err.contains("1Password item newitem1 in vault vaultid1")
                    && err.contains("by hand"),
                "{err}"
            );
            assert!(!err.contains(FAKE), "{err}");
            assert_eq!(account_count(&path2), 0);
            f.assert_no_secret_in_argv();
        }

        #[tokio::test]
        async fn the_suggested_source_follows_what_is_available() {
            let f = Fakes::new();
            let mut script = Script::answering(&[""]);
            let kind = ask_source_kind(&f.stores(), &mut script)
                .await
                .expect("ask");
            assert_eq!(kind, SourceKind::OnePassword);
            assert_eq!(script.defaults[0].as_deref(), Some("1password"));
            assert!(
                script.questions[0].contains("1password, keychain, env, command"),
                "{:?}",
                script.questions
            );

            // `op` without an account is not offered.
            f.write("op.accounts", "[]");
            let mut script = Script::answering(&[""]);
            let kind = ask_source_kind(&f.stores(), &mut script)
                .await
                .expect("ask");
            assert_eq!(kind, SourceKind::Keychain);
            assert!(!script.questions[0].contains("1password"));

            let mut script = Script::answering(&[""]);
            let kind = ask_source_kind(&SecretStores::default(), &mut script)
                .await
                .expect("ask");
            assert_eq!(kind, SourceKind::Env);
            assert_eq!(script.questions[0], "Password source (env, command)");

            // Never chosen without a terminal, even when 1Password is there.
            f.write(
                "op.accounts",
                r#"[{"url":"my.1password.com","account_uuid":"ACCOUNTUUID1"}]"#,
            );
            let err = ask_source_kind(&f.stores(), &mut Script::offline())
                .await
                .expect_err("no terminal")
                .to_string();
            assert!(err.contains("--password-source"), "{err}");
        }

        #[tokio::test]
        async fn keychain_service_override_is_limited_to_stalwart_mcp_names() {
            let f = Fakes::new();
            let (_d, path) = temp_config();
            let verifier = FakeVerifier::default();
            let mut args = add_args("work", &KEYCHAIN_STDIN);
            args.extend(["--keychain-service".into(), "stalwart-mcp-test".into()]);
            let (result, out) =
                run_in(&args, &path, &mut stdin_script(), &verifier, &f.stores()).await;
            assert!(result.expect("add"), "{out}");
            assert!(
                f.read("security.stdin")
                    .contains(r#"-s "stalwart-mcp-test""#)
            );
            let config = AppConfig::load(Some(&path)).expect("load");
            let argv = config.accounts[0].password_command.clone().expect("argv");
            assert_eq!(argv[3], "stalwart-mcp-test");

            // Without the override the item is not recognised as ours.
            let remove: Vec<String> = ["remove", "work", "--yes", "--delete-secret"]
                .map(String::from)
                .to_vec();
            let (result, _) = run_in(
                &remove,
                &path,
                &mut Script::offline(),
                &verifier,
                &f.stores(),
            )
            .await;
            assert!(result.is_err());
            let mut remove = remove;
            remove.extend(["--keychain-service".into(), "stalwart-mcp-test".into()]);
            let (result, out) = run_in(
                &remove,
                &path,
                &mut Script::offline(),
                &verifier,
                &f.stores(),
            )
            .await;
            assert!(result.expect("remove"), "{out}");
            assert!(!f.path("item.work").exists());

            for bad in ["login", "stalwart-mcp-", "stalwart-mcp-a b", "Stalwart-mcp"] {
                assert!(
                    with_keychain_service(&f.stores(), Some(bad)).is_err(),
                    "{bad}"
                );
            }
        }
    }
}
