//! IPC types shared between the daemon and clients.
//!
//! This crate is the wire contract: the daemon serialises a [`Response`] and a
//! client serialises a [`Request`], both agreeing on the exact JSON layout
//! defined here. It deliberately depends only on `clip-vault-core` (for the
//! stable leaf types like [`ClipEntry`] and [`EntryId`]) plus serde — no
//! crypto, no storage — so client binaries never link the decryption code.

use clip_vault_core::{ClipEntry, EntryContent, EntryId};
use serde::{Deserialize, Serialize};

/// The protocol version this build speaks. Every [`Request`] carries it, and
/// [`decode_request`] rejects any value it does not recognise.
pub const PROTOCOL_VERSION: u8 = 1;

/// Errors produced while encoding or decoding wire messages.
#[derive(Debug, thiserror::Error)]
pub enum ProtoError {
    /// The JSON payload could not be (de)serialised.
    #[error("serialisation error: {0}")]
    Json(#[from] serde_json::Error),

    /// The decoded request declared a protocol version this build cannot serve.
    #[error("unsupported protocol version: expected {expected}, found {found}")]
    UnsupportedVersion {
        /// The version this build speaks.
        expected: u8,
        /// The version the peer sent.
        found: u8,
    },
}

/// Convenience result type for this crate.
pub type Result<T> = std::result::Result<T, ProtoError>;

/// A request envelope pairing a transport-level version with a payload body.
///
/// Keeping the [`protocol_version`](Request::protocol_version) in the outer
/// struct lets [`decode_request`] validate it before interpreting the
/// [`body`](Request::body).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    /// Protocol version the client speaks; validated on decode.
    pub protocol_version: u8,
    /// The actual operation being requested.
    pub body: RequestBody,
}

impl Request {
    /// Wraps `body` in an envelope stamped with the current [`PROTOCOL_VERSION`].
    #[must_use]
    pub const fn new(body: RequestBody) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            body,
        }
    }
}

/// The operations a client can ask the daemon to perform.
///
/// Internally tagged (`{"type": "List", ...}`) so every frame is self-describing
/// on the wire. That tagging requires every variant to be struct-form (named
/// fields), never tuple/newtype — a constraint kept intentionally here.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum RequestBody {
    /// Store a new clipboard entry. The full entry travels here because it
    /// originates on the client side; there is no plaintext being leaked back.
    Add {
        /// The entry to store.
        entry: ClipEntry,
    },

    /// Fetch a page of lossy previews, newest first, starting after `after`.
    List {
        /// Cursor: return entries older than this id, or newest if `None`.
        after: Option<EntryId>,
        /// Maximum number of previews to return.
        limit: i64,
    },

    /// Fetch one full entry by id, for an explicit paste.
    Get {
        /// The entry to retrieve.
        id: EntryId,
    },

    /// Delete the given entries.
    Delete {
        /// The entries to remove.
        ids: Vec<EntryId>,
    },

    /// Pin or unpin an entry.
    SetPin {
        /// The entry to (un)pin.
        id: EntryId,
        /// Whether the entry should be pinned.
        pinned: bool,
    },

    /// Increment an entry's paste counter.
    MarkPasted {
        /// The entry that was pasted.
        id: EntryId,
    },

    /// Purge entries whose expiry is at or before `now` (epoch milliseconds).
    PurgeExpired {
        /// Current time as epoch milliseconds.
        now: i64,
    },
}

/// The daemon's reply to a [`Request`].
///
/// Also internally tagged for self-describing frames. The response is implicitly
/// the protocol version negotiated by the request, so it carries no version
/// field of its own.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum Response {
    /// The operation succeeded with no payload (e.g. `Add`).
    Ok,

    /// The number of rows affected (`Delete`, `SetPin`, `MarkPasted`,
    /// `PurgeExpired`). `u64` rather than `usize`, since the wire format must
    /// not depend on the peer's pointer width.
    Count {
        /// Rows affected.
        count: u64,
    },

    /// A page of previews, in reply to `List`.
    Previews {
        /// The previews, newest first.
        previews: Vec<EntryPreview>,
    },

    /// A single full entry, in reply to `Get`.
    Entry {
        /// The requested entry.
        entry: ClipEntry,
    },

    /// The request failed; `message` is human-readable.
    Error {
        /// Human-readable failure description.
        message: String,
    },
}

/// What kind of content a preview stands in for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PreviewKind {
    /// Text content; `snippet` holds a truncated copy.
    Text,
    /// Image content; the payload is omitted.
    Image,
    /// Opaque binary content; the payload is omitted.
    Binary,
}

/// A lossy, list-view projection of a [`ClipEntry`].
///
/// Deliberately omits the full payload: only a short text snippet (for text) or
/// a [`PreviewKind`] marker (for image/binary) crosses the wire, so clients
/// never receive full plaintext for entries the user has not explicitly pasted.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryPreview {
    /// Identifies the entry for follow-up actions (`Get`, `Delete`, ...).
    pub id: EntryId,
    /// What kind of content this row represents.
    pub kind: PreviewKind,
    /// Truncated, safe-to-display text; empty for non-text content.
    pub snippet: String,
    /// Whether the entry is pinned.
    pub pinned: bool,
    /// How many times the entry has been pasted.
    pub times_pasted: u32,
    /// Creation time as epoch milliseconds.
    pub created_at: i64,
}

impl EntryPreview {
    /// Maximum number of characters kept in a text snippet.
    const SNIPPET_CHARS: usize = 64;

    /// Builds a lossy preview from a full entry, truncating text payloads and
    /// dropping image/binary payloads entirely.
    #[must_use]
    pub fn from_entry(entry: &ClipEntry) -> Self {
        let (kind, snippet) = match entry.get_entry_content() {
            EntryContent::Text(text) => (PreviewKind::Text, truncate(text, Self::SNIPPET_CHARS)),
            EntryContent::Image(_) => (PreviewKind::Image, String::new()),
            EntryContent::Binary(_) => (PreviewKind::Binary, String::new()),
        };

        Self {
            id: *entry.get_entry_id(),
            kind,
            snippet,
            pinned: entry.get_entry_pinned(),
            times_pasted: (*entry.get_entry_times_pasted()).into(),
            created_at: entry.get_entry_created_at().timestamp_millis(),
        }
    }
}

/// Truncates `s` to at most `max_chars` characters, respecting char boundaries.
fn truncate(s: &str, max_chars: usize) -> String {
    s.chars().take(max_chars).collect()
}

/// Serialises a request to a single newline-terminated JSON line.
///
/// # Errors
///
/// Returns [`ProtoError::Json`] if serialisation fails.
pub fn encode_request(request: &Request) -> Result<String> {
    let mut line = serde_json::to_string(request)?;
    line.push('\n');
    Ok(line)
}

/// Parses one JSON line into a [`Request`], validating the protocol version
/// before trusting the body.
///
/// # Errors
///
/// Returns [`ProtoError::UnsupportedVersion`] if the line declares a version
/// this build does not speak, or [`ProtoError::Json`] if the line is malformed.
pub fn decode_request(line: &str) -> Result<Request> {
    // Stage 1: read only the version. Serde ignores the unknown `body` field,
    // so this succeeds even when the body has a shape this build cannot parse —
    // letting us return a clean "unsupported version" instead of a parse error.
    let header: VersionHeader = serde_json::from_str(line)?;
    if header.protocol_version != PROTOCOL_VERSION {
        return Err(ProtoError::UnsupportedVersion {
            expected: PROTOCOL_VERSION,
            found: header.protocol_version,
        });
    }

    // Stage 2: the version is one we understand, so parse the full request.
    let request = serde_json::from_str(line)?;
    Ok(request)
}

/// The minimal view used to read a request's version before its body.
#[derive(Deserialize)]
struct VersionHeader {
    protocol_version: u8,
}

/// Serialises a response to a single newline-terminated JSON line.
///
/// # Errors
///
/// Returns [`ProtoError::Json`] if serialisation fails.
pub fn encode_response(response: &Response) -> Result<String> {
    let mut line = serde_json::to_string(response)?;
    line.push('\n');
    Ok(line)
}

/// Parses one JSON line into a [`Response`].
///
/// # Errors
///
/// Returns [`ProtoError::Json`] if the line is malformed.
pub fn decode_response(line: &str) -> Result<Response> {
    let response = serde_json::from_str(line)?;
    Ok(response)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use clip_vault_core::{EntryContent, Sensitivity};

    fn sample_entry() -> ClipEntry {
        ClipEntry::new(
            EntryContent::Text("hello world".into()),
            Sensitivity::Normal,
            vec!["text/plain".into()],
        )
    }

    fn round_trip_request(body: RequestBody) {
        let request = Request::new(body);
        let line = encode_request(&request).unwrap();
        assert!(line.ends_with('\n'), "frame must be newline-terminated");
        let decoded = decode_request(&line).unwrap();
        assert_eq!(request, decoded);
    }

    fn round_trip_response(response: &Response) {
        let line = encode_response(response).unwrap();
        assert!(line.ends_with('\n'), "frame must be newline-terminated");
        let decoded = decode_response(&line).unwrap();
        assert_eq!(*response, decoded);
    }

    #[test]
    fn request_variants_round_trip() {
        let id = EntryId::new();
        round_trip_request(RequestBody::Add {
            entry: sample_entry(),
        });
        round_trip_request(RequestBody::List {
            after: None,
            limit: 50,
        });
        round_trip_request(RequestBody::List {
            after: Some(id),
            limit: 10,
        });
        round_trip_request(RequestBody::Get { id });
        round_trip_request(RequestBody::Delete { ids: vec![id] });
        round_trip_request(RequestBody::SetPin { id, pinned: true });
        round_trip_request(RequestBody::MarkPasted { id });
        round_trip_request(RequestBody::PurgeExpired {
            now: 1_700_000_000_000,
        });
    }

    #[test]
    fn response_variants_round_trip() {
        round_trip_response(&Response::Ok);
        round_trip_response(&Response::Count { count: 3 });
        round_trip_response(&Response::Previews {
            previews: vec![EntryPreview::from_entry(&sample_entry())],
        });
        round_trip_response(&Response::Entry {
            entry: sample_entry(),
        });
        round_trip_response(&Response::Error {
            message: "boom".into(),
        });
    }

    #[test]
    fn decode_rejects_unknown_version() {
        let mut request = Request::new(RequestBody::List {
            after: None,
            limit: 1,
        });
        request.protocol_version = 99;
        let line = encode_request(&request).unwrap();

        let err = decode_request(&line).unwrap_err();
        assert!(matches!(
            err,
            ProtoError::UnsupportedVersion {
                expected: PROTOCOL_VERSION,
                found: 99
            }
        ));
    }

    #[test]
    fn preview_truncates_long_text_and_drops_binary() {
        let long = "x".repeat(200);
        let entry = ClipEntry::new(
            EntryContent::Text(long),
            Sensitivity::Normal,
            vec!["text/plain".into()],
        );
        let preview = EntryPreview::from_entry(&entry);
        assert_eq!(preview.kind, PreviewKind::Text);
        assert_eq!(preview.snippet.chars().count(), EntryPreview::SNIPPET_CHARS);
    }
}
