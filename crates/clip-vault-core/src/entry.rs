use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Unique Id type
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EntryId(Uuid);

/// Mime type
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct MimeType(String);

/// Number of time the content pasted
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct PasteCount(u32);

/// Binary payload holder for clip content
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryPayload {
    data: Vec<u8>,
    mime: MimeType,
}

/// Entry content holder, could be text, image or raw binary
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryContent {
    /// text content
    Text(String),

    /// image content
    Image(BinaryPayload),

    /// binary content
    Binary(BinaryPayload),
}

/// Sensitivity levels
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Sensitivity {
    /// Not sensitive content
    Normal,

    /// Sensitive content
    Sensitive(SensitiveReason),
}

/// Sensitivity reasons
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SensitiveReason {
    /// Mime reported sensitivity reason
    MimeHint(MimeType),

    /// Pattern match reported sensitivity reason
    PatternMatch(String),

    /// User reported sensitivity reason
    UserForced,
}

/// Structure that holds the clip entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClipEntry {
    id: EntryId,
    content: EntryContent,
    sensitivity: Sensitivity,
    mime_types: Vec<MimeType>,
    times_pasted: PasteCount,
    pinned: bool,
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
}

impl From<&str> for MimeType {
    fn from(s: &str) -> Self {
        Self(s.to_string())
    }
}

impl From<String> for MimeType {
    fn from(s: String) -> Self {
        Self(s)
    }
}

impl EntryId {
    /// Creates a new entry id
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::now_v7())
    }

    /// Returns the 16-byte representation, for storage/serialization.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        self.0.as_bytes()
    }

    /// Reconstructs an `EntryId` from its 16-byte representation.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(Uuid::from_bytes(bytes))
    }
}

impl Default for EntryId {
    fn default() -> Self {
        Self::new()
    }
}

impl ClipEntry {
    /// Creates a new Clip Entry
    #[must_use]
    pub fn new(content: EntryContent, sensitivity: Sensitivity, mime_types: Vec<MimeType>) -> Self {
        Self {
            id: EntryId::default(),
            content,
            sensitivity,
            mime_types,
            times_pasted: PasteCount(0),
            pinned: false,
            created_at: Utc::now(),
            expires_at: None,
        }
    }
}

#[cfg(test)]
mod tests {

    use super::*;

    #[test]
    #[allow(clippy::expect_used)]
    fn clip_entry_serde_round_trip() {
        let entry = ClipEntry {
            id: EntryId::new(),
            content: EntryContent::Text("Hello World".into()),
            sensitivity: Sensitivity::Normal,
            mime_types: vec!["text/plain".into()],
            times_pasted: PasteCount(5),
            pinned: false,
            created_at: Utc::now(),
            expires_at: None,
        };

        let mut bytes = Vec::new();
        ciborium::ser::into_writer(&entry, &mut bytes).expect("encode failed");
        let decoded: ClipEntry = ciborium::de::from_reader(&bytes[..]).expect("decode failed");

        assert_eq!(entry, decoded);
    }

    #[test]
    #[allow(clippy::expect_used)]
    fn entry_id_is_time_sortable() {
        let first = EntryId::new();
        std::thread::sleep(std::time::Duration::from_millis(2));
        let second = EntryId::new();

        assert!(
            first.0 < second.0,
            "expected first ({first:?}) to sort before second ({second:?})"
        );
    }
}
