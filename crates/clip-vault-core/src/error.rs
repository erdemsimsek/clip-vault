use rusqlite::Error as SqliteError;
use thiserror::Error;

/// Convenience result alias for clip-vault-core.
pub type Result<T> = std::result::Result<T, Error>;

/// Error types used in the Clip-Vault
#[derive(Error, Debug)]
pub enum Error {
    /// Vault is locked.
    #[error("vault is locked")]
    VaultLocked,

    /// Operation cancelled by user.
    #[error("operation aborted by the user")]
    OperationCancelled,

    /// Password is not correct.
    #[error("password is not correct")]
    WrongPassword,

    /// Entry could not be found in the database.
    #[error("entry not found, entry: {0}")]
    EntryNotFound(String),

    /// Cryptographic operation failed.
    #[error("crypto error")]
    Crypto(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// `SQLite` or other storage backend failure.
    #[error("storage error: {0}")]
    Storage(#[from] SqliteError),

    /// System keyring (libsecret / kwallet) failure.
    #[error("keyring error")]
    Keyring(#[source] Box<dyn std::error::Error + Send + Sync>),

    /// Configuration file contains error.
    #[error("config error: {0}")]
    Config(String),

    /// Filesystem or other I/O failure.
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}
