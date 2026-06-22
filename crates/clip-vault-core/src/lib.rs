//! Core library: encrypted storage, AES-256-GCM, clipboard entry types.

mod crypto;
mod entry;
mod error;

pub use entry::{
    BinaryPayload, ClipEntry, EntryContent, EntryId, MimeType, PasteCount, SensitiveReason,
    Sensitivity,
};

pub use error::{Error, Result};

pub use crypto::{
    EncryptedEntry, KdfParams, WrappedDek, decrypt_entry, derive_kek, encrypt_entry, generate_dek,
    unwrap_dek, wrap_dek,
};
