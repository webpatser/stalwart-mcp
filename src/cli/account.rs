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
//! later failure rolls back.

use super::{CliError, Prompter, Verifier};
use crate::config::{AccountConfig, AppConfig, DEFAULT_PASSWORD_ENV};
use crate::config_edit::{
    AccountEntry, AccountUpdate, ConfigDocument, DefaultAccountChange, PasswordSetting,
};
use crate::secret::{DEFAULT_COMMAND_TIMEOUT, Secret, run_password_command};
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
}

/// Run one `account` subcommand against the config at `path`. Returns
/// `Ok(false)` when `test` found a failing account.
pub async fn run(
    command: AccountCommand,
    path: &Path,
    prompter: &mut impl Prompter,
    verifier: &impl Verifier,
    out: &mut impl Write,
) -> Result<bool, CliError> {
    match command {
        AccountCommand::Add(args) => add(args, path, prompter, verifier, out).await?,
        AccountCommand::List { json } => list(path, json, out)?,
        AccountCommand::Edit(args) => edit(args, path, prompter, verifier, out).await?,
        AccountCommand::Remove(args) => remove(args, path, prompter, out)?,
        AccountCommand::Test { name } => return test(path, name.as_deref(), verifier, out).await,
    }
    Ok(true)
}

/// A password source picked for an account, before anything is stored.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChosenSource {
    /// Read from this environment variable.
    Env(String),
    /// Run this argv; the program is an absolute path.
    Command(Vec<String>),
}

/// A secret this run wrote into a store (1Password, Keychain), kept so a later
/// failure can undo exactly that. The env and command sources store nothing.
#[derive(Debug)]
pub enum StoredSecret {}

/// A rollback that did not succeed: the item to remove by hand and why.
#[derive(Debug)]
pub struct RollbackFailed {
    pub item: String,
    pub reason: String,
}

impl StoredSecret {
    /// Delete what this run stored. `Ok` names what was removed.
    pub async fn roll_back(self) -> Result<String, RollbackFailed> {
        match self {}
    }
}

impl ChosenSource {
    /// The password to verify with, obtained in memory: the variable's value,
    /// or the output of one run of the command.
    pub async fn password(&self, account: &str) -> Result<Secret, CliError> {
        match self {
            Self::Env(var) => std::env::var(var).map(Secret::new).map_err(|_| {
                CliError::Failed(format!(
                    "environment variable '{var}' is not set (or not valid UTF-8); set it, or \
                     pass --no-verify to write the account without checking it"
                ))
            }),
            Self::Command(argv) => run_password_command(argv, DEFAULT_COMMAND_TIMEOUT)
                .await
                .map_err(|e| {
                    CliError::Failed(format!(
                        "account '{account}': the password command failed: {e}"
                    ))
                }),
        }
    }

    /// Store the secret for sources that hold one, and return the setting to
    /// write plus the handle that undoes the store.
    pub async fn store(
        &self,
        _account: &str,
        _password: Option<&Secret>,
    ) -> Result<(PasswordSetting, Option<StoredSecret>), CliError> {
        match self {
            Self::Env(var) => Ok((PasswordSetting::Env(var.clone()), None)),
            Self::Command(argv) => Ok((PasswordSetting::Command(argv.clone()), None)),
        }
    }
}

/// Turn the source flags (and, when interactive, answers) into a source.
/// `required` is false for `edit`, where no source flag means "keep it".
/// `current` is the account's present setting, used for prompt defaults.
pub fn choose_source(
    args: &SourceArgs,
    current: Option<&PasswordSetting>,
    required: bool,
    prompter: &mut impl Prompter,
) -> Result<Option<ChosenSource>, CliError> {
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
    let kind = match kind {
        Some(kind) => kind,
        None if args.password_stdin => {
            return Err(CliError::NotAvailable(
                "--password-stdin (for the 1password and keychain sources)".into(),
            ));
        }
        None if !required => return Ok(None),
        None => ask_source_kind(prompter)?,
    };
    match kind {
        SourceKind::OnePassword => {
            Err(CliError::NotAvailable("--password-source 1password".into()))
        }
        SourceKind::Keychain => Err(CliError::NotAvailable("--password-source keychain".into())),
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

fn ask_source_kind(prompter: &mut impl Prompter) -> Result<SourceKind, CliError> {
    if !prompter.interactive() {
        return Err(CliError::Usage(
            "missing --password-source (env or command) and no terminal to ask on".into(),
        ));
    }
    let answer = prompter.ask("Password source (env, command)", Some("env"))?;
    let answer = answer.trim();
    let answer = if answer.is_empty() { "env" } else { answer };
    SourceKind::from_str(answer, true)
        .map_err(|_| CliError::Usage(format!("unknown password source '{answer}'")))
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

fn is_executable_file(path: &Path) -> bool {
    let Ok(meta) = std::fs::metadata(path) else {
        return false;
    };
    if !meta.is_file() {
        return false;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        meta.permissions().mode() & 0o111 != 0
    }
    #[cfg(not(unix))]
    {
        true
    }
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

async fn add(
    args: AddArgs,
    path: &Path,
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
    let source = choose_source(&args.source, None, true, prompter)?
        .ok_or_else(|| CliError::Usage("missing --password-source".into()))?;

    let probe = AccountEntry {
        name: name.clone(),
        url: url.clone(),
        username: username.clone(),
        password: PasswordSetting::DefaultEnv,
    };
    let password = if args.no_verify {
        None
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

    let (setting, stored) = source.store(&name, password.as_ref()).await?;
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
    if args.no_verify {
        writeln!(
            out,
            "Credentials not checked (--no-verify); run `stalwart-mcp account test {name}`"
        )?;
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

async fn edit(
    args: EditArgs,
    path: &Path,
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
    let source = choose_source(&args.source, Some(&current.password), false, prompter)?;
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

    let password = if !args.no_verify && (url_changed || username_changed || source.is_some()) {
        let password = match &source {
            Some(source) => source.password(&new_name).await?,
            None => account_config(&probe).resolve_password().await?,
        };
        verify(verifier, &account_config(&probe), &password, out).await?;
        Some(password)
    } else {
        None
    };

    confirm(
        args.yes,
        &format!("Change account '{}' in {}?", current.name, path.display()),
        prompter,
    )?;

    let (setting, stored) = match &source {
        Some(source) => {
            let (setting, stored) = source.store(&new_name, password.as_ref()).await?;
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
    }
    if args.default {
        writeln!(out, "'{new_name}' is the default account")?;
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

fn remove(
    args: RemoveArgs,
    path: &Path,
    prompter: &mut impl Prompter,
    out: &mut impl Write,
) -> Result<(), CliError> {
    let mut doc = ConfigDocument::load_or_new(path)?;
    let entry = doc
        .accounts()?
        .into_iter()
        .find(|a| a.name == args.name)
        .ok_or_else(|| no_account(&args.name, path))?;

    if args.delete_secret {
        return Err(match SourceDescription::of(&entry.password) {
            SourceDescription::Keychain => {
                CliError::NotAvailable("--delete-secret for Keychain items".into())
            }
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

    /// Scripted answers; records the questions asked.
    #[derive(Debug, Default)]
    struct Script {
        interactive: bool,
        answers: VecDeque<String>,
        questions: Vec<String>,
    }

    impl Script {
        fn offline() -> Self {
            Self::default()
        }

        fn answering(answers: &[&str]) -> Self {
            Self {
                interactive: true,
                answers: answers.iter().map(|a| a.to_string()).collect(),
                questions: Vec::new(),
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
        fn ask(&mut self, question: &str, _default: Option<&str>) -> Result<String, CliError> {
            self.next(question)
        }
        fn ask_secret(&mut self, question: &str) -> Result<Secret, CliError> {
            self.next(question).map(Secret::new)
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

    async fn run_with(
        args: &[String],
        path: &Path,
        prompter: &mut Script,
        verifier: &FakeVerifier,
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
        let result = run(action, path, prompter, verifier, &mut out).await;
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
    async fn stores_and_typed_password_sources_are_not_available_yet() {
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
        for extra in [
            &["--password-source", "1password"][..],
            &["--password-source", "keychain"],
            &["--op-reference", "op://vault/item/password"],
            &["--op-vault", "Private"],
            &["--password-stdin"],
            &["--password-source", "keychain", "--password-stdin"],
        ] {
            let args: Vec<String> = base.iter().chain(extra).map(|a| a.to_string()).collect();
            let (result, _) = run_with(&args, &path, &mut Script::offline(), &verifier).await;
            let err = result.expect_err("not available");
            assert!(matches!(err, CliError::NotAvailable(_)), "{extra:?}: {err}");
            assert!(err.to_string().contains("not available yet"), "{err}");
        }
        // Mismatched source flags are usage errors.
        for extra in [
            &["--password-source", "env", "--password-command", "/bin/sh"][..],
            &["--password-source", "command", "--password-env", "X"],
            &["--password-source", "env", "--password-stdin"],
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
    async fn remove_delete_secret_for_a_keychain_account_is_not_available_yet() {
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
        let (result, _) = run_with(
            &args,
            &path,
            &mut Script::offline(),
            &FakeVerifier::default(),
        )
        .await;
        assert!(matches!(result, Err(CliError::NotAvailable(_))));
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
}
