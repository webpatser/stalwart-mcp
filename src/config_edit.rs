//! Comment-preserving, atomic editing of the config file's accounts.
//!
//! [`ConfigDocument`] keeps the file as a `toml_edit` document, so comments,
//! formatting and unknown keys outside the edited account block survive a
//! save unchanged. Accounts written as `[[accounts]]` tables can be edited; an
//! inline `accounts = [...]` array is read but never written.
//!
//! [`ConfigDocument::save`] writes a temp file in the target's own directory
//! (after resolving a symlinked config, so the symlink stays), with the mode of
//! the original file (0600 for a new one), fsyncs it and renames it over the
//! target. The save is refused when the file changed on disk since it was
//! loaded. A new file is created with mode 0600, missing directories with 0700.

use crate::config::{AppConfig, DEFAULT_PASSWORD_ENV};
use crate::error::AppError;
use figment::Figment;
use figment::providers::{Format, Toml};
use std::fs::{self, File, OpenOptions};
use std::io::{ErrorKind, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use toml_edit::{Array, ArrayOfTables, DocumentMut, Item, Table, TableLike, Value};

/// How an account's password is configured.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PasswordSetting {
    /// Neither `password_env` nor `password_command`: the password is read from
    /// [`DEFAULT_PASSWORD_ENV`].
    DefaultEnv,
    /// `password_env = "<VAR>"`.
    Env(String),
    /// `password_command = [argv...]`.
    Command(Vec<String>),
}

impl PasswordSetting {
    /// The environment variable read for an env source, `None` for a command.
    pub fn env_var(&self) -> Option<&str> {
        match self {
            Self::DefaultEnv => Some(DEFAULT_PASSWORD_ENV),
            Self::Env(var) => Some(var),
            Self::Command(_) => None,
        }
    }
}

/// One account as written in the config file. Holds no secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AccountEntry {
    pub name: String,
    pub url: String,
    pub username: String,
    pub password: PasswordSetting,
}

/// The fields to change on an existing account; `None` leaves a field as is.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AccountUpdate {
    /// New name (rename). A `default_account` naming the old name follows.
    pub name: Option<String>,
    pub url: Option<String>,
    pub username: Option<String>,
    pub password: Option<PasswordSetting>,
}

/// What [`ConfigDocument::remove_account`] did to `default_account`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DefaultAccountChange {
    /// `default_account` did not name the removed account.
    Unchanged,
    /// The removed account was the default; the default is now this account.
    Moved(String),
    /// The removed account was the default and no account remains, so the
    /// `default_account` key was removed.
    Cleared,
}

/// The config file as an editable document.
#[derive(Debug)]
pub struct ConfigDocument {
    /// The path given by the caller.
    path: PathBuf,
    /// The file actually written: `path` with a symlink resolved.
    target: PathBuf,
    doc: DocumentMut,
    /// The bytes read at load (or last save); `None` when the file did not exist.
    original: Option<String>,
    /// Permission bits of the original file.
    #[cfg(unix)]
    mode: Option<u32>,
    #[cfg(not(unix))]
    permissions: Option<fs::Permissions>,
}

const ACCOUNTS: &str = "accounts";
const DEFAULT_ACCOUNT: &str = "default_account";

impl ConfigDocument {
    /// Load the config at `path`, or start an empty document when the file
    /// does not exist (it is created by [`Self::save`]). A symlinked config is
    /// resolved, so a save replaces the file it points to.
    pub fn load_or_new(path: &Path) -> Result<Self, AppError> {
        let target = resolve_target(path)?;
        let shown = path.display();
        let (original, meta) = match File::open(&target) {
            Ok(mut file) => {
                let meta = file
                    .metadata()
                    .map_err(|e| AppError::Config(format!("Cannot read {shown}: {e}")))?;
                if !meta.is_file() {
                    return Err(AppError::Config(format!("{shown} is not a regular file")));
                }
                let mut content = String::new();
                file.read_to_string(&mut content)
                    .map_err(|e| AppError::Config(format!("Cannot read {shown}: {e}")))?;
                (Some(content), Some(meta))
            }
            Err(e) if e.kind() == ErrorKind::NotFound => (None, None),
            Err(e) => return Err(AppError::Config(format!("Cannot open {shown}: {e}"))),
        };
        let doc = match &original {
            Some(content) => content
                .parse::<DocumentMut>()
                .map_err(|e| AppError::Config(format!("Cannot parse {shown}: {e}")))?,
            None => DocumentMut::new(),
        };
        Ok(Self {
            path: path.to_path_buf(),
            target,
            doc,
            original,
            #[cfg(unix)]
            mode: meta.map(|m| {
                use std::os::unix::fs::PermissionsExt;
                m.permissions().mode() & 0o7777
            }),
            #[cfg(not(unix))]
            permissions: meta.map(|m| m.permissions()),
        })
    }

    /// The path given to [`Self::load_or_new`].
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// True when the file did not exist at load and has not been saved yet.
    pub fn is_new(&self) -> bool {
        self.original.is_none()
    }

    /// The rendered document, as [`Self::save`] would write it.
    pub fn render(&self) -> String {
        self.doc.to_string()
    }

    /// The accounts in file order, from `[[accounts]]` tables or an inline
    /// `accounts = [...]` array.
    pub fn accounts(&self) -> Result<Vec<AccountEntry>, AppError> {
        match self.doc.get(ACCOUNTS) {
            None | Some(Item::None) => Ok(Vec::new()),
            Some(Item::ArrayOfTables(aot)) => aot
                .iter()
                .enumerate()
                .map(|(i, t)| read_entry(t, i))
                .collect(),
            Some(Item::Value(Value::Array(array))) => array
                .iter()
                .enumerate()
                .map(|(i, v)| match v {
                    Value::InlineTable(t) => read_entry(t, i),
                    _ => Err(AppError::Config(format!(
                        "accounts entry {} is not a table",
                        i + 1
                    ))),
                })
                .collect(),
            Some(_) => Err(AppError::Config(
                "accounts must be a list of [[accounts]] tables".into(),
            )),
        }
    }

    /// The `default_account` value, if set.
    pub fn default_account(&self) -> Option<&str> {
        self.doc.get(DEFAULT_ACCOUNT).and_then(Item::as_str)
    }

    /// Append a new `[[accounts]]` block. Refused when the name is taken or
    /// the accounts are an inline array.
    pub fn add_account(&mut self, entry: &AccountEntry) -> Result<(), AppError> {
        if self.accounts()?.iter().any(|a| a.name == entry.name) {
            return Err(AppError::Config(format!(
                "An account named '{}' already exists",
                entry.name
            )));
        }
        let mut table = Table::new();
        table.insert("name", toml_edit::value(entry.name.as_str()));
        table.insert("url", toml_edit::value(entry.url.as_str()));
        table.insert("username", toml_edit::value(entry.username.as_str()));
        set_password(&mut table, &entry.password);

        // When the new block becomes the last table, it goes after the text
        // that ends the file (toml_edit keeps that as document trailing, which
        // would otherwise follow the new block), so the file only grows at
        // its end.
        let mut max = None;
        max_table_position(self.doc.as_table(), &mut max);
        let last_account_position = self
            .editable_accounts()?
            .and_then(|aot| aot.iter().last().map(Table::position));
        let renders_last = match last_account_position {
            None => true,
            Some(pos) => pos.is_some() && pos == max,
        };
        if renders_last {
            table.set_position(max.map_or(0, |m| m + 1));
            let trailing = self.doc.trailing().as_str().unwrap_or_default().to_string();
            if !trailing.is_empty() {
                let mut prefix = trailing;
                if !prefix.ends_with('\n') {
                    prefix.push('\n');
                }
                if !prefix.ends_with("\n\n") {
                    prefix.push('\n');
                }
                table.decor_mut().set_prefix(prefix);
                self.doc.set_trailing("");
            }
        }

        if self.editable_accounts()?.is_none() {
            self.doc
                .insert(ACCOUNTS, Item::ArrayOfTables(ArrayOfTables::new()));
        }
        self.editable_accounts()?
            .ok_or_else(|| AppError::Config("accounts table missing after insert".into()))?
            .push(table);
        Ok(())
    }

    /// Change the given fields of account `name`; other keys, comments and
    /// formatting in its block stay. A rename also renames `default_account`.
    pub fn update_account(&mut self, name: &str, update: &AccountUpdate) -> Result<(), AppError> {
        if let Some(new_name) = &update.name
            && new_name != name
            && self.accounts()?.iter().any(|a| &a.name == new_name)
        {
            return Err(AppError::Config(format!(
                "An account named '{new_name}' already exists"
            )));
        }
        let index = self.index_of(name)?;
        let aot = self.editable_accounts()?.ok_or_else(|| not_found(name))?;
        let table = aot.get_mut(index).ok_or_else(|| not_found(name))?;
        if let Some(v) = &update.name {
            set_value(table, "name", Value::from(v.as_str()));
        }
        if let Some(v) = &update.url {
            set_value(table, "url", Value::from(v.as_str()));
        }
        if let Some(v) = &update.username {
            set_value(table, "username", Value::from(v.as_str()));
        }
        if let Some(password) = &update.password {
            set_password(table, password);
        }
        if let Some(new_name) = &update.name
            && self.default_account() == Some(name)
        {
            set_value(
                self.doc.as_table_mut(),
                DEFAULT_ACCOUNT,
                Value::from(new_name.as_str()),
            );
        }
        Ok(())
    }

    /// Remove account `name` (its block and the comments directly above it).
    /// When it was the default, `default_account` moves to the first remaining
    /// account, or is removed when none remains.
    pub fn remove_account(&mut self, name: &str) -> Result<DefaultAccountChange, AppError> {
        let index = self.index_of(name)?;
        let aot = self.editable_accounts()?.ok_or_else(|| not_found(name))?;
        aot.remove(index);
        let first_remaining = aot
            .iter()
            .next()
            .and_then(|t| t.get("name"))
            .and_then(Item::as_str)
            .map(str::to_string);
        if aot.is_empty() {
            self.doc.remove(ACCOUNTS);
        }
        if self.default_account() != Some(name) {
            return Ok(DefaultAccountChange::Unchanged);
        }
        match first_remaining {
            Some(next) => {
                set_value(
                    self.doc.as_table_mut(),
                    DEFAULT_ACCOUNT,
                    Value::from(next.as_str()),
                );
                Ok(DefaultAccountChange::Moved(next))
            }
            None => {
                self.doc.remove(DEFAULT_ACCOUNT);
                Ok(DefaultAccountChange::Cleared)
            }
        }
    }

    /// Set `default_account` to an existing account.
    pub fn set_default(&mut self, name: &str) -> Result<(), AppError> {
        if !self.accounts()?.iter().any(|a| a.name == name) {
            return Err(not_found(name));
        }
        set_value(self.doc.as_table_mut(), DEFAULT_ACCOUNT, Value::from(name));
        Ok(())
    }

    /// Write the document atomically. Refused when the rendered config would
    /// not load, or when the file changed on disk since it was loaded.
    pub fn save(&mut self) -> Result<(), AppError> {
        let rendered = self.render();
        self.check_loadable(&rendered)?;

        let dir = parent_dir(&self.target).to_path_buf();
        if self.original.is_none() {
            create_private_dir(&dir)?;
        }
        let (mut file, temp) = create_temp(&dir, &self.target)?;
        let guard = TempGuard(Some(temp));
        let temp_path = guard.path();

        self.apply_mode(&file)?;
        file.write_all(rendered.as_bytes())
            .and_then(|()| file.sync_all())
            .map_err(|e| AppError::Config(format!("Cannot write {}: {e}", temp_path.display())))?;
        drop(file);

        self.check_unchanged()?;
        fs::rename(temp_path, &self.target).map_err(|e| {
            AppError::Config(format!("Cannot replace {}: {e}", self.target.display()))
        })?;
        guard.disarm();
        sync_dir(&dir)?;

        if self.original.is_none() {
            #[cfg(unix)]
            {
                self.mode = Some(0o600);
            }
        }
        self.original = Some(rendered);
        Ok(())
    }

    /// The `[[accounts]]` array for editing; `None` when there is none yet,
    /// an error for an inline array.
    fn editable_accounts(&mut self) -> Result<Option<&mut ArrayOfTables>, AppError> {
        let path = &self.path;
        match self.doc.get_mut(ACCOUNTS) {
            None | Some(Item::None) => Ok(None),
            Some(Item::ArrayOfTables(aot)) => Ok(Some(aot)),
            Some(Item::Value(Value::Array(_))) => Err(AppError::Config(format!(
                "{} lists its accounts as an inline array (accounts = [...]), which this \
                 command does not edit; rewrite them as [[accounts]] tables first",
                path.display()
            ))),
            Some(_) => Err(AppError::Config(format!(
                "accounts in {} is not a list of [[accounts]] tables",
                path.display()
            ))),
        }
    }

    /// Index of account `name`; refuses inline arrays before looking.
    fn index_of(&mut self, name: &str) -> Result<usize, AppError> {
        self.editable_accounts()?;
        self.accounts()?
            .iter()
            .position(|a| a.name == name)
            .ok_or_else(|| not_found(name))
    }

    /// The rendered config must parse and pass the load-time account checks.
    fn check_loadable(&self, rendered: &str) -> Result<(), AppError> {
        let config: AppConfig = Figment::from(Toml::string(rendered))
            .extract()
            .map_err(|e| AppError::Config(format!("Edited config would not load: {e}")))?;
        config
            .validate_accounts()
            .map_err(|e| AppError::Config(format!("Edited config would not load: {e}")))
    }

    /// Refuse when the target no longer holds the bytes read at load.
    fn check_unchanged(&self) -> Result<(), AppError> {
        let shown = self.path.display();
        let changed = match (fs::read(&self.target), &self.original) {
            (Ok(now), Some(original)) => now != original.as_bytes(),
            (Err(e), None) if e.kind() == ErrorKind::NotFound => false,
            (Ok(_), None) => true,
            (Err(e), Some(_)) if e.kind() == ErrorKind::NotFound => true,
            (Err(e), _) => {
                return Err(AppError::Config(format!("Cannot re-read {shown}: {e}")));
            }
        };
        if changed {
            return Err(AppError::Config(format!(
                "{shown} changed on disk since it was loaded; nothing was written, run the \
                 command again"
            )));
        }
        Ok(())
    }

    #[cfg(unix)]
    fn apply_mode(&self, file: &File) -> Result<(), AppError> {
        use std::os::unix::fs::PermissionsExt;
        let mode = self.mode.unwrap_or(0o600);
        file.set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|e| AppError::Config(format!("Cannot set the mode of the temp file: {e}")))
    }

    #[cfg(not(unix))]
    fn apply_mode(&self, file: &File) -> Result<(), AppError> {
        match &self.permissions {
            Some(p) => file.set_permissions(p.clone()).map_err(|e| {
                AppError::Config(format!("Cannot set the mode of the temp file: {e}"))
            }),
            None => Ok(()),
        }
    }
}

fn not_found(name: &str) -> AppError {
    AppError::NotFound(format!("No account named '{name}'"))
}

/// `path`, or the file it points to when it is a symlink.
fn resolve_target(path: &Path) -> Result<PathBuf, AppError> {
    match fs::symlink_metadata(path) {
        Ok(meta) if meta.file_type().is_symlink() => fs::canonicalize(path).map_err(|e| {
            AppError::Config(format!(
                "Cannot resolve the symlinked config {}: {e}",
                path.display()
            ))
        }),
        _ => Ok(path.to_path_buf()),
    }
}

fn parent_dir(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

/// Create `dir` and missing parents with mode 0700.
fn create_private_dir(dir: &Path) -> Result<(), AppError> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder
        .create(dir)
        .map_err(|e| AppError::Config(format!("Cannot create {}: {e}", dir.display())))
}

/// A new, empty temp file next to `target`, mode 0600 from creation on.
fn create_temp(dir: &Path, target: &Path) -> Result<(File, PathBuf), AppError> {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let stem = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "config.toml".into());
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or_default();
    let mut last_err = None;
    for _ in 0..16 {
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let temp = dir.join(format!(".{stem}.{}.{nanos}.{n}.tmp", std::process::id()));
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&temp) {
            Ok(file) => return Ok((file, temp)),
            Err(e) if e.kind() == ErrorKind::AlreadyExists => last_err = Some(e),
            Err(e) => {
                return Err(AppError::Config(format!(
                    "Cannot create a temp file in {}: {e}",
                    dir.display()
                )));
            }
        }
    }
    Err(AppError::Config(format!(
        "Cannot create a temp file in {}: {}",
        dir.display(),
        last_err.map(|e| e.to_string()).unwrap_or_default()
    )))
}

#[cfg(unix)]
fn sync_dir(dir: &Path) -> Result<(), AppError> {
    File::open(dir)
        .and_then(|d| d.sync_all())
        .map_err(|e| AppError::Config(format!("Cannot sync {}: {e}", dir.display())))
}

#[cfg(not(unix))]
fn sync_dir(_dir: &Path) -> Result<(), AppError> {
    Ok(())
}

/// Removes the temp file unless disarmed after the rename.
struct TempGuard(Option<PathBuf>);

impl TempGuard {
    fn path(&self) -> &Path {
        self.0.as_deref().unwrap_or_else(|| Path::new(""))
    }

    fn disarm(mut self) {
        self.0 = None;
    }
}

impl Drop for TempGuard {
    fn drop(&mut self) {
        if let Some(path) = self.0.take() {
            let _ = fs::remove_file(path);
        }
    }
}

/// The highest `position` of any table below `table`.
fn max_table_position(table: &Table, max: &mut Option<usize>) {
    for (_, item) in table.iter() {
        let tables: Vec<&Table> = match item {
            Item::Table(t) => vec![t],
            Item::ArrayOfTables(aot) => aot.iter().collect(),
            _ => continue,
        };
        for t in tables {
            if let Some(pos) = t.position() {
                *max = Some(max.map_or(pos, |m| m.max(pos)));
            }
            max_table_position(t, max);
        }
    }
}

/// Replace the value of `key`, keeping its surrounding whitespace and comment,
/// or insert the key when it is missing.
fn set_value(table: &mut Table, key: &str, new: Value) {
    match table.get_mut(key).and_then(Item::as_value_mut) {
        Some(old) => {
            let decor = old.decor().clone();
            *old = new;
            *old.decor_mut() = decor;
        }
        None => {
            table.insert(key, Item::Value(new));
        }
    }
}

/// Write the password keys; the key of the other source is removed.
fn set_password(table: &mut Table, password: &PasswordSetting) {
    match password {
        PasswordSetting::DefaultEnv => {
            table.remove("password_env");
            table.remove("password_command");
        }
        PasswordSetting::Env(var) => {
            table.remove("password_command");
            set_value(table, "password_env", Value::from(var.as_str()));
        }
        PasswordSetting::Command(argv) => {
            table.remove("password_env");
            let array: Array = argv.iter().map(String::as_str).collect();
            set_value(table, "password_command", Value::Array(array));
        }
    }
}

fn read_entry(table: &dyn TableLike, index: usize) -> Result<AccountEntry, AppError> {
    let field = |key: &str| -> Result<String, AppError> {
        table
            .get(key)
            .and_then(Item::as_str)
            .map(str::to_string)
            .ok_or_else(|| {
                AppError::Config(format!(
                    "accounts entry {} has no string '{key}'",
                    index + 1
                ))
            })
    };
    let name = field("name")?;
    let env = match table.get("password_env") {
        None | Some(Item::None) => None,
        Some(item) => Some(item.as_str().map(str::to_string).ok_or_else(|| {
            AppError::Config(format!("Account '{name}': password_env must be a string"))
        })?),
    };
    let command = match table.get("password_command") {
        None | Some(Item::None) => None,
        Some(item) => {
            let bad = || {
                AppError::Config(format!(
                    "Account '{name}': password_command must be a list of strings"
                ))
            };
            let array = item.as_array().ok_or_else(bad)?;
            Some(
                array
                    .iter()
                    .map(|v| v.as_str().map(str::to_string).ok_or_else(bad))
                    .collect::<Result<Vec<_>, _>>()?,
            )
        }
    };
    let password = match (env, command) {
        (Some(_), Some(_)) => {
            return Err(AppError::Config(format!(
                "Account '{name}' sets both password_env and password_command; keep only one"
            )));
        }
        (Some(var), None) => PasswordSetting::Env(var),
        (None, Some(argv)) => PasswordSetting::Command(argv),
        (None, None) => PasswordSetting::DefaultEnv,
    };
    Ok(AccountEntry {
        url: field("url")?,
        username: field("username")?,
        name,
        password,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str) -> AccountEntry {
        AccountEntry {
            name: name.into(),
            url: "https://mail.example.com".into(),
            username: format!("{name}@example.com"),
            password: PasswordSetting::DefaultEnv,
        }
    }

    /// A 0700 temp dir holding `config.toml` (0600) with `content`.
    fn existing(content: &str) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("config.toml");
        fs::write(&path, content).expect("write");
        #[cfg(unix)]
        {
            set_mode(dir.path(), 0o700);
            set_mode(&path, 0o600);
        }
        (dir, path)
    }

    #[cfg(unix)]
    fn set_mode(path: &Path, mode: u32) {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("chmod");
    }

    #[cfg(unix)]
    fn mode_of(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        fs::metadata(path).expect("metadata").permissions().mode() & 0o7777
    }

    fn no_temp_files(dir: &Path) {
        let leftovers: Vec<_> = fs::read_dir(dir)
            .expect("read_dir")
            .filter_map(Result::ok)
            .filter(|e| e.file_name().to_string_lossy().ends_with(".tmp"))
            .collect();
        assert!(leftovers.is_empty(), "{leftovers:?}");
    }

    #[test]
    fn creates_a_missing_file_with_private_modes() {
        let base = tempfile::tempdir().expect("tempdir");
        let dir = base.path().join("nested").join("stalwart-mcp");
        let path = dir.join("config.toml");
        let mut doc = ConfigDocument::load_or_new(&path).expect("new");
        assert!(doc.is_new());
        assert!(doc.accounts().expect("accounts").is_empty());
        doc.add_account(&entry("a")).expect("add");
        doc.set_default("a").expect("default");
        doc.save().expect("save");
        assert!(!doc.is_new());
        #[cfg(unix)]
        {
            assert_eq!(mode_of(&dir), 0o700);
            assert_eq!(mode_of(&path), 0o600);
        }
        let config = AppConfig::load(Some(&path)).expect("loadable");
        assert_eq!(config.accounts[0].name, "a");
        assert_eq!(config.default_account.as_deref(), Some("a"));
        no_temp_files(&dir);

        // A second save of the same document works (the saved bytes are the new baseline).
        doc.add_account(&entry("b")).expect("add b");
        doc.save().expect("second save");
        assert_eq!(
            AppConfig::load(Some(&path)).expect("load").accounts.len(),
            2
        );
    }

    const HEAD: &str = "# Top comment\n\
        default_account = \"a\" # the default\n\
        future_key = { x = 1 }\n\
        \n\
        # account a\n\
        [[accounts]]\n\
        name = \"a\"   # spaced\n\
        url = \"https://a.example.com\"\n\
        username = \"a@example.com\"\n\
        password_env = \"A_PASSWORD\"\n\
        note = \"unknown key\"\n";
    const TAIL: &str = "\n\
        # server settings\n\
        [server]\n\
        bind   =   \"127.0.0.1:3001\"\n\
        unknown = [1, 2,   3]\n\
        \n\
        [capabilities]\n\
        send = false # keep\n\
        # trailing comment\n";

    #[test]
    fn add_keeps_everything_outside_the_new_block() {
        let original = format!("{HEAD}{TAIL}");
        let (_dir, path) = existing(&original);
        let mut doc = ConfigDocument::load_or_new(&path).expect("load");
        assert_eq!(
            doc.render(),
            original,
            "untouched document renders unchanged"
        );
        doc.add_account(&AccountEntry {
            password: PasswordSetting::Env("B_PASSWORD".into()),
            ..entry("b")
        })
        .expect("add");
        doc.save().expect("save");

        let written = fs::read_to_string(&path).expect("read");
        assert!(written.starts_with(HEAD), "{written}");
        assert!(written.ends_with(TAIL), "{written}");
        let middle = &written[HEAD.len()..written.len() - TAIL.len()];
        assert!(
            middle.contains("[[accounts]]") && middle.contains("name = \"b\""),
            "{middle}"
        );
        assert!(middle.contains("password_env = \"B_PASSWORD\""), "{middle}");

        let names: Vec<_> = doc
            .accounts()
            .expect("accounts")
            .into_iter()
            .map(|a| a.name)
            .collect();
        assert_eq!(names, ["a", "b"]);
        assert!(doc.add_account(&entry("b")).is_err(), "duplicate refused");
    }

    #[test]
    fn add_after_trailing_comments_appends_at_the_end() {
        for original in [
            "# only a comment\n",
            "# no final newline",
            "[[accounts]]\nname = \"a\"\nurl = \"u\"\nusername = \"x\"\n\n# trailing comment\n",
        ] {
            let (_dir, path) = existing(original);
            let mut doc = ConfigDocument::load_or_new(&path).expect("load");
            doc.add_account(&entry("b")).expect("add");
            doc.add_account(&entry("c")).expect("add");
            doc.save().expect("save");
            let written = fs::read_to_string(&path).expect("read");
            assert!(written.starts_with(original), "{written}");
            let rest = &written[original.len()..];
            let (b, c) = (rest.find("name = \"b\""), rest.find("name = \"c\""));
            assert!(b.is_some() && c.is_some() && b < c, "{written}");
        }
    }

    #[test]
    fn update_and_rename_keep_other_keys_and_the_default() {
        let original = format!("{HEAD}{TAIL}");
        let (_dir, path) = existing(&original);
        let mut doc = ConfigDocument::load_or_new(&path).expect("load");
        let argv = vec!["/usr/bin/security".to_string(), "-w".to_string()];
        doc.update_account(
            "a",
            &AccountUpdate {
                name: Some("work".into()),
                url: Some("https://work.example.com".into()),
                password: Some(PasswordSetting::Command(argv.clone())),
                ..Default::default()
            },
        )
        .expect("update");
        doc.save().expect("save");

        let written = fs::read_to_string(&path).expect("read");
        assert!(
            written.starts_with("# Top comment\ndefault_account = \"work\" # the default\n"),
            "{written}"
        );
        assert!(
            written.contains("name = \"work\"   # spaced\n"),
            "{written}"
        );
        assert!(written.contains("note = \"unknown key\""), "{written}");
        assert!(!written.contains("password_env"), "{written}");
        assert!(written.ends_with(TAIL), "{written}");

        let accounts = doc.accounts().expect("accounts");
        assert_eq!(
            accounts,
            [AccountEntry {
                name: "work".into(),
                url: "https://work.example.com".into(),
                username: "a@example.com".into(),
                password: PasswordSetting::Command(argv),
            }]
        );
        assert_eq!(doc.default_account(), Some("work"));

        // Back to an env source drops password_command.
        doc.update_account(
            "work",
            &AccountUpdate {
                password: Some(PasswordSetting::Env("W".into())),
                ..Default::default()
            },
        )
        .expect("update");
        let rendered = doc.render();
        assert!(
            rendered.contains("password_env = \"W\"") && !rendered.contains("password_command")
        );

        // Renaming onto an existing name and updating a missing account fail.
        doc.add_account(&entry("other")).expect("add");
        let rename = AccountUpdate {
            name: Some("other".into()),
            ..Default::default()
        };
        assert!(doc.update_account("work", &rename).is_err());
        assert!(matches!(
            doc.update_account("missing", &AccountUpdate::default()),
            Err(AppError::NotFound(_))
        ));
    }

    #[test]
    fn removing_the_default_moves_it_then_clears_it() {
        let (_dir, path) = existing(&format!("{HEAD}{TAIL}"));
        let mut doc = ConfigDocument::load_or_new(&path).expect("load");
        doc.add_account(&entry("b")).expect("add b");
        doc.add_account(&entry("c")).expect("add c");

        assert_eq!(
            doc.remove_account("c").expect("remove c"),
            DefaultAccountChange::Unchanged
        );
        assert_eq!(
            doc.remove_account("a").expect("remove a"),
            DefaultAccountChange::Moved("b".into())
        );
        assert_eq!(doc.default_account(), Some("b"));
        doc.save().expect("save");
        let config = AppConfig::load(Some(&path)).expect("load");
        assert_eq!(config.default_account.as_deref(), Some("b"));
        assert_eq!(config.accounts.len(), 1);

        assert_eq!(
            doc.remove_account("b").expect("remove b"),
            DefaultAccountChange::Cleared
        );
        assert_eq!(doc.default_account(), None);
        assert!(doc.accounts().expect("accounts").is_empty());
        doc.save().expect("save empty");
        let written = fs::read_to_string(&path).expect("read");
        assert!(
            !written.contains("default_account") && !written.contains("[[accounts]]"),
            "{written}"
        );
        assert!(written.ends_with(TAIL), "{written}");
        assert!(matches!(
            doc.remove_account("b"),
            Err(AppError::NotFound(_))
        ));
    }

    #[test]
    fn inline_array_is_read_but_not_written() {
        let original = "default_account = \"x\"\naccounts = [\n  { name = \"x\", url = \"https://x.example.com\", username = \"x@example.com\", password_command = [\"/bin/echo\", \"hi\"] },\n  { name = \"y\", url = \"https://y.example.com\", username = \"y@example.com\" },\n]\n";
        let (_dir, path) = existing(original);
        let mut doc = ConfigDocument::load_or_new(&path).expect("load");
        let accounts = doc.accounts().expect("accounts");
        assert_eq!(accounts.len(), 2);
        assert_eq!(
            accounts[0].password,
            PasswordSetting::Command(vec!["/bin/echo".into(), "hi".into()])
        );
        assert_eq!(accounts[1].password, PasswordSetting::DefaultEnv);

        let errors = [
            doc.add_account(&entry("z")).expect_err("add"),
            doc.update_account("x", &AccountUpdate::default())
                .expect_err("update"),
            doc.remove_account("y").expect_err("remove"),
        ];
        for err in errors {
            let msg = err.to_string();
            assert!(
                msg.contains("inline array") && msg.contains("[[accounts]]"),
                "{msg}"
            );
        }
        assert_eq!(fs::read_to_string(&path).expect("read"), original);
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_config_keeps_the_symlink() {
        let base = tempfile::tempdir().expect("tempdir");
        let real_dir = base.path().join("real");
        create_private_dir(&real_dir).expect("dir");
        let real = real_dir.join("config.toml");
        fs::write(&real, "# real file\n").expect("write");
        set_mode(&real, 0o600);
        let link = base.path().join("link.toml");
        std::os::unix::fs::symlink(&real, &link).expect("symlink");

        let mut doc = ConfigDocument::load_or_new(&link).expect("load");
        doc.add_account(&entry("a")).expect("add");
        doc.save().expect("save");

        assert!(
            fs::symlink_metadata(&link)
                .expect("meta")
                .file_type()
                .is_symlink()
        );
        let written = fs::read_to_string(&real).expect("read");
        assert!(
            written.starts_with("# real file\n") && written.contains("name = \"a\""),
            "{written}"
        );
        no_temp_files(&real_dir);
        no_temp_files(base.path());
    }

    #[cfg(unix)]
    #[test]
    fn existing_mode_is_kept() {
        for mode in [0o600, 0o640] {
            let (dir, path) = existing("# c\n");
            set_mode(&path, mode);
            let mut doc = ConfigDocument::load_or_new(&path).expect("load");
            doc.add_account(&entry("a")).expect("add");
            doc.save().expect("save");
            assert_eq!(mode_of(&path), mode);
            no_temp_files(dir.path());
        }
    }

    #[test]
    fn change_on_disk_between_load_and_save_is_refused() {
        let (dir, path) = existing("# v1\n");
        let mut doc = ConfigDocument::load_or_new(&path).expect("load");
        doc.add_account(&entry("a")).expect("add");
        fs::write(&path, "# v2, edited elsewhere\n").expect("write");
        let err = doc.save().expect_err("refused").to_string();
        assert!(err.contains("changed on disk"), "{err}");
        assert_eq!(
            fs::read_to_string(&path).expect("read"),
            "# v2, edited elsewhere\n"
        );
        no_temp_files(dir.path());

        // A file created after a new document was started is not overwritten.
        let new_path = dir.path().join("new.toml");
        let mut doc = ConfigDocument::load_or_new(&new_path).expect("new");
        doc.add_account(&entry("a")).expect("add");
        fs::write(&new_path, "# appeared\n").expect("write");
        assert!(
            doc.save()
                .expect_err("refused")
                .to_string()
                .contains("changed on disk")
        );
        assert_eq!(fs::read_to_string(&new_path).expect("read"), "# appeared\n");
    }

    #[test]
    fn password_command_with_special_characters_round_trips() {
        let base = tempfile::tempdir().expect("tempdir");
        let path = base.path().join("cfg").join("config.toml");
        let argv: Vec<String> = [
            "/Applications/My Tools/pw",
            "say \"hello\"",
            "it's",
            "back\\slash\\",
            "tab\tand ''' and \"\"\"",
            "op://Vault Name/item/password",
        ]
        .map(String::from)
        .to_vec();
        let mut doc = ConfigDocument::load_or_new(&path).expect("new");
        doc.add_account(&AccountEntry {
            password: PasswordSetting::Command(argv.clone()),
            ..entry("a")
        })
        .expect("add");
        doc.save().expect("save");

        let config = AppConfig::load(Some(&path)).expect("load");
        assert_eq!(
            config.accounts[0].password_command.as_deref(),
            Some(argv.as_slice())
        );
        assert_eq!(config.accounts[0].password_env, None);
        let reread = ConfigDocument::load_or_new(&path).expect("reload");
        assert_eq!(
            reread.accounts().expect("accounts")[0].password,
            PasswordSetting::Command(argv)
        );
    }

    #[test]
    fn save_refuses_a_config_that_would_not_load() {
        let (_dir, path) = existing("");
        let mut doc = ConfigDocument::load_or_new(&path).expect("load");
        doc.add_account(&AccountEntry {
            password: PasswordSetting::Command(Vec::new()),
            ..entry("a")
        })
        .expect("add");
        let err = doc.save().expect_err("refused").to_string();
        assert!(err.contains("would not load"), "{err}");
        assert_eq!(fs::read_to_string(&path).expect("read"), "");
        assert!(matches!(
            doc.set_default("nope"),
            Err(AppError::NotFound(_))
        ));
    }
}
