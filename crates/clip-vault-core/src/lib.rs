//! Core library: encrypted storage, AES-256-GCM, clipboard entry types.

mod entry;
mod error;

pub use entry::{
    BinaryPayload, ClipEntry, EntryContent, EntryId, MimeType, PasteCount, SensitiveReason,
    Sensitivity,
};

pub use error::{Error, Result};
