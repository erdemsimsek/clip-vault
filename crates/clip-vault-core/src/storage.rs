use crate::{EntryId, Error};
use directories::ProjectDirs;
use rusqlite::types::{FromSql, FromSqlError, FromSqlResult, ToSql, ToSqlOutput, ValueRef};
use rusqlite::{Connection, OptionalExtension};
use rusqlite_migration::{M, Migrations};

const MIGRATIONS_SLICE: &[M<'_>] = &[
    M::up(
        "
                CREATE TABLE vault (
                id INTEGER PRIMARY KEY CHECK (id = 1),
                data BLOB NOT NULL,
                created_at INTEGER NOT NULL)
        ",
    ),
    M::up(
        "
                CREATE TABLE entries (
                id BLOB PRIMARY KEY,
                blob BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                expires_at INTEGER,
                pinned INTEGER NOT NULL DEFAULT 0,
                times_pasted INTEGER NOT NULL DEFAULT 0,
                content_kind TEXT NOT NULL)
            ",
    ),
    M::up(
        "CREATE INDEX idx_entries_expires_at ON entries(expires_at) WHERE expires_at IS NOT NULL",
    ),
];

const MIGRATIONS: Migrations<'_> = Migrations::from_slice(MIGRATIONS_SLICE);

/// Coarse content type for filtering — the Store's index, not the crypto detail.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentKind {
    /// Text content type
    Text,

    /// Image content type
    Image,

    /// Blob data content type
    Binary,
}

/// Plaintext, queryable attributes for a stored entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EntryMeta {
    /// Creation timestamp
    pub created_at: i64, // epoch millis

    /// Optional expiry date for entry.
    pub expires_at: Option<i64>,

    /// Pin status.
    pub pinned: bool,

    /// Number of times the entry is pasted.
    pub times_pasted: u32,

    /// Entry content type.
    pub content_kind: ContentKind,
}

/// A row as it comes out of the Store: id + opaque payload + attributes.
#[derive(Debug, Clone)]
pub struct StoredEntry {
    /// Unique entry id
    pub id: EntryId,

    /// Blob entry data
    pub blob: Vec<u8>,

    /// Entry metadata
    pub meta: EntryMeta,
}

/// Sqlite Database Handle.
pub struct Storage {
    handle: Connection,
}

impl ToSql for EntryId {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        self.as_bytes().as_slice().to_sql() // delegate to &[u8]'s ToSql
    }
}

impl FromSql for EntryId {
    fn column_result(v: ValueRef<'_>) -> FromSqlResult<Self> {
        let bytes: [u8; 16] = v
            .as_blob()?
            .try_into()
            .map_err(|_| FromSqlError::InvalidType)?;
        Ok(Self::from_bytes(bytes))
    }
}

impl ToSql for ContentKind {
    fn to_sql(&self) -> rusqlite::Result<ToSqlOutput<'_>> {
        let s = match self {
            Self::Text => "text",
            Self::Image => "image",
            Self::Binary => "binary",
        };
        s.to_sql()
    }
}

impl FromSql for ContentKind {
    fn column_result(v: ValueRef<'_>) -> FromSqlResult<Self> {
        match v.as_str()? {
            "text" => Ok(Self::Text),
            "image" => Ok(Self::Image),
            "binary" => Ok(Self::Binary),
            _ => Err(FromSqlError::InvalidType),
        }
    }
}

impl Storage {
    /// Creates a new database;
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if any rusqlite operation fails.
    pub fn new(mut connection: Connection) -> crate::Result<Self> {
        connection.pragma_update_and_check(None, "journal_mode", "WAL", |_| Ok(()))?;
        connection.pragma_update(None, "foreign_keys", "ON")?;
        connection.pragma_update(None, "busy_timeout", 5000)?;
        MIGRATIONS.to_latest(&mut connection)?;
        Ok(Self { handle: connection })
    }

    /// In-memory store for tests — real schema and migrations, no files.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if any rusqlite operation fails.
    #[cfg(test)]
    pub(crate) fn in_memory() -> crate::Result<Self> {
        Self::new(Connection::open_in_memory()?)
    }

    /// Open the database connection.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if the DB path cannot be found.
    /// Returns [`Error::Storage`] if any rusqlite operation fails.
    pub fn open() -> crate::Result<Self> {
        let dir = ProjectDirs::from("info", "erdemsimsek", "clip-vault")
            .ok_or_else(|| Error::Config("DB path cannot be found".to_string()))?;
        std::fs::create_dir_all(dir.data_local_dir())?;
        let conn = Connection::open(dir.data_local_dir().join("clip-vault.db"))?;
        Self::new(conn) // ← production: a file connection
    }

    /// Save vault metadata to rusqlite DB.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if any rusqlite operation fails.
    pub fn save_vault(&self, blob: &[u8]) -> crate::Result<()> {
        self.handle.execute(
            "
                INSERT or REPLACE INTO vault (id, data, created_at) VALUES (1, ?1, ?2)
            ",
            (&blob, chrono::Utc::now().timestamp_millis()),
        )?;

        Ok(())
    }

    /// Loads vault metadata to the application.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if any rusqlite operation fails.
    pub fn load_vault(&self) -> crate::Result<Option<Vec<u8>>> {
        let data = self
            .handle
            .query_one(
                "SELECT data FROM vault WHERE id = 1",
                [],                             // no params
                |row| row.get::<_, Vec<u8>>(0), // pull column 0 (the blob) as Vec<u8>
            )
            .optional()?;

        Ok(data)
    }

    /// Adds a new clipboard entry to the DB.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if any rusqlite operation fails.
    pub fn add(&self, id: EntryId, blob: &[u8], meta: &EntryMeta) -> crate::Result<()> {
        self.handle.execute("
                INSERT INTO entries (id, blob, created_at, expires_at, pinned, times_pasted, content_kind)
                    VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
            ", (id, blob, meta.created_at, meta.expires_at, meta.pinned, meta.times_pasted, meta.content_kind))?;
        Ok(())
    }

    /// Retrives Retrieves the stored entries in the DB.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if any rusqlite operation fails.
    pub fn list(&self, after: Option<EntryId>, limit: i64) -> crate::Result<Vec<StoredEntry>> {
        let mut stmt = self.handle.prepare(
          "SELECT id, blob, created_at, expires_at, pinned, times_pasted, content_kind FROM entries
                WHERE (?1 IS NULL OR id < ?1) ORDER BY id DESC LIMIT ?2")?;

        let rows = stmt.query_map(rusqlite::params![after, limit], |row| {
            Ok(StoredEntry {
                id: row.get(0)?,
                blob: row.get(1)?,
                meta: EntryMeta {
                    created_at: row.get(2)?,
                    expires_at: row.get(3)?,
                    pinned: row.get(4)?,
                    times_pasted: row.get(5)?,
                    content_kind: row.get(6)?,
                },
            })
        })?;

        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }

    /// Deletes the entries with mathing IDs in the DB.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if any rusqlite operation fails.
    pub fn delete(&self, ids: &[EntryId]) -> crate::Result<usize> {
        let placeholders = vec!["?"; ids.len()].join(", ");
        let sql = format!("DELETE FROM entries WHERE id IN ({placeholders})");
        let count = self.handle.execute(&sql, rusqlite::params_from_iter(ids))?;

        Ok(count)
    }

    /// Pins/Unpins the entry for the given entry id.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if any rusqlite operation fails.
    pub fn set_pin(&self, id: &EntryId, pin_state: bool) -> crate::Result<usize> {
        let count = self.handle.execute(
            "UPDATE entries SET pinned = ?1 WHERE id = ?2",
            rusqlite::params![pin_state, id],
        )?;
        Ok(count)
    }

    /// Increments the `times_pasted` value for the give entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if any rusqlite operation fails.
    pub fn mark_pasted(&self, id: &EntryId) -> crate::Result<usize> {
        let count = self.handle.execute(
            "UPDATE entries SET times_pasted = times_pasted + 1 WHERE id = ?1",
            rusqlite::params![id],
        )?;

        Ok(count)
    }

    /// Deletes the expired entries that aren't pinned.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if any rusqlite operation fails.
    pub fn purge_expired(&self, now: i64) -> crate::Result<usize> {
        let count = self.handle.execute(
            "DELETE FROM entries WHERE expires_at < ?1 and pinned = 0",
            rusqlite::params![now],
        )?;
        Ok(count)
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {

    use super::*;

    fn create_tables() -> Connection {
        let mut conn = rusqlite::Connection::open_in_memory().unwrap();
        MIGRATIONS.to_latest(&mut conn).unwrap();
        conn
    }

    #[test]
    fn check_table_exist() {
        let conn = create_tables();

        let exist: bool = conn
            .query_row(
                "SELECT EXISTS(
            SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
                rusqlite::params!["entries"],
                |row| row.get(0),
            )
            .unwrap();

        assert!(exist);

        let exist: bool = conn
            .query_row(
                "SELECT EXISTS(
            SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?1)",
                rusqlite::params!["vault"],
                |row| row.get(0),
            )
            .unwrap();

        assert!(exist);
    }

    #[test]
    fn check_save_vault() {
        let conn = create_tables();
        let storage = Storage::new(conn).unwrap();

        let blob_test_data: [u8; 10] = [5; 10];
        storage.save_vault(&blob_test_data).unwrap();

        let blob_readback = storage.load_vault().unwrap().unwrap();

        assert_eq!(blob_test_data, blob_readback.as_slice());
    }

    #[test]
    fn load_vault_none_when_empty() {
        let conn = create_tables();
        let storage = Storage::new(conn).unwrap();

        assert_eq!(storage.load_vault().unwrap(), None);
    }

    #[test]
    fn list_orders_newest_first() {
        let conn = create_tables();
        let storage = Storage::new(conn).unwrap();

        let entry_id: EntryId = EntryId::new();
        let metadata: EntryMeta = EntryMeta {
            created_at: (1),
            expires_at: Some(2),
            pinned: (false),
            times_pasted: (1),
            content_kind: (ContentKind::Text),
        };
        let blob_test_data: [u8; 10] = [5; 10];

        storage.add(entry_id, &blob_test_data, &metadata).unwrap();

        let entry_id2: EntryId = EntryId::new();
        storage.add(entry_id2, &blob_test_data, &metadata).unwrap();

        let entries = storage.list(None, 1).unwrap();

        assert_eq!(entry_id2, entries[0].id);
    }

    #[test]
    fn list_respects_limit() {
        let conn = create_tables();
        let storage = Storage::new(conn).unwrap();

        let entry_id: EntryId = EntryId::new();
        let metadata: EntryMeta = EntryMeta {
            created_at: (1),
            expires_at: Some(2),
            pinned: (false),
            times_pasted: (1),
            content_kind: (ContentKind::Text),
        };
        let blob_test_data: [u8; 10] = [5; 10];

        storage.add(entry_id, &blob_test_data, &metadata).unwrap();

        let entry_id2: EntryId = EntryId::new();
        storage.add(entry_id2, &blob_test_data, &metadata).unwrap();

        let entry_id3: EntryId = EntryId::new();
        storage.add(entry_id3, &blob_test_data, &metadata).unwrap();

        let entries = storage.list(None, 2).unwrap();
        assert_eq!(entries.len(), 2);
    }

    #[test]
    fn list_cursor_returns_older_only() {
        let conn = create_tables();
        let storage = Storage::new(conn).unwrap();

        let entry_id: EntryId = EntryId::new();
        let metadata: EntryMeta = EntryMeta {
            created_at: (1),
            expires_at: Some(2),
            pinned: (false),
            times_pasted: (1),
            content_kind: (ContentKind::Text),
        };
        let blob_test_data: [u8; 10] = [5; 10];

        storage.add(entry_id, &blob_test_data, &metadata).unwrap();

        let entry_id2: EntryId = EntryId::new();
        storage.add(entry_id2, &blob_test_data, &metadata).unwrap();

        let entry_id3: EntryId = EntryId::new();
        storage.add(entry_id3, &blob_test_data, &metadata).unwrap();

        let entries = storage.list(Some(entry_id2), 1).unwrap();

        assert_eq!(entry_id, entries[0].id);
    }

    #[test]
    fn delete_multiple_ids() {
        let conn = create_tables();
        let storage = Storage::new(conn).unwrap();

        let entry_id: EntryId = EntryId::new();
        let metadata: EntryMeta = EntryMeta {
            created_at: (1),
            expires_at: Some(2),
            pinned: (false),
            times_pasted: (1),
            content_kind: (ContentKind::Text),
        };
        let blob_test_data: [u8; 10] = [5; 10];

        storage.add(entry_id, &blob_test_data, &metadata).unwrap();

        let entry_id2: EntryId = EntryId::new();
        storage.add(entry_id2, &blob_test_data, &metadata).unwrap();

        let entry_id3: EntryId = EntryId::new();
        storage.add(entry_id3, &blob_test_data, &metadata).unwrap();

        let rows_affected = storage.delete(&[entry_id, entry_id2, entry_id3]).unwrap();

        assert_eq!(rows_affected, [entry_id, entry_id2, entry_id3].len());
    }

    #[test]
    fn delete_empty_is_noop() {
        let conn = create_tables();
        let storage = Storage::new(conn).unwrap();

        let rows_affected = storage.delete(&[]).unwrap();
        assert_eq!(rows_affected, 0);
    }

    #[test]
    fn purge_keeps_unexpired() {
        let conn = create_tables();
        let storage = Storage::new(conn).unwrap();

        let entry_id: EntryId = EntryId::new();
        let metadata: EntryMeta = EntryMeta {
            created_at: (1),
            expires_at: Some(200),
            pinned: (false),
            times_pasted: (1),
            content_kind: (ContentKind::Text),
        };
        let blob_test_data: [u8; 10] = [5; 10];

        storage.add(entry_id, &blob_test_data, &metadata).unwrap();

        let rows_affected = storage.purge_expired(5).unwrap();
        assert_eq!(rows_affected, 0);
    }

    #[test]
    fn check_save_entry() {
        let conn = create_tables();
        let storage = Storage::new(conn).unwrap();

        let entry_id: EntryId = EntryId::new();
        let metadata: EntryMeta = EntryMeta {
            created_at: (1),
            expires_at: Some(2),
            pinned: (false),
            times_pasted: (1),
            content_kind: (ContentKind::Text),
        };
        let blob_test_data: [u8; 10] = [5; 10];

        storage.add(entry_id, &blob_test_data, &metadata).unwrap();

        let stored_entry = storage.list(None, 1).unwrap();
        assert_eq!(stored_entry.len(), 1);

        assert_eq!(entry_id, stored_entry[0].id);
        assert_eq!(metadata, stored_entry[0].meta);
        assert_eq!(blob_test_data, stored_entry[0].blob.as_slice());

        storage.set_pin(&entry_id, true).unwrap();
        let stored_entry = storage.list(None, 1).unwrap();
        assert_eq!(stored_entry.len(), 1);
        assert!(stored_entry[0].meta.pinned);

        storage.mark_pasted(&entry_id).unwrap();
        let stored_entry = storage.list(None, 1).unwrap();
        assert_eq!(stored_entry.len(), 1);
        assert_eq!(stored_entry[0].meta.times_pasted, 2);
    }

    #[test]
    fn check_purge_entry() {
        let conn = create_tables();
        let storage = Storage::new(conn).unwrap();

        let entry_id: EntryId = EntryId::new();
        let metadata: EntryMeta = EntryMeta {
            created_at: (1),
            expires_at: Some(2),
            pinned: (false),
            times_pasted: (1),
            content_kind: (ContentKind::Text),
        };
        let blob_test_data: [u8; 10] = [5; 10];

        storage.add(entry_id, &blob_test_data, &metadata).unwrap();

        let number_of_row_affected = storage.purge_expired(3).unwrap();
        assert!(number_of_row_affected > 0);
    }

    #[test]
    fn check_purge_doesnot_delete_pinned_entry() {
        let conn = create_tables();
        let storage = Storage::new(conn).unwrap();

        let entry_id: EntryId = EntryId::new();
        let metadata: EntryMeta = EntryMeta {
            created_at: (1),
            expires_at: Some(2),
            pinned: (true),
            times_pasted: (1),
            content_kind: (ContentKind::Text),
        };
        let blob_test_data: [u8; 10] = [5; 10];

        storage.add(entry_id, &blob_test_data, &metadata).unwrap();

        let number_of_row_affected = storage.purge_expired(3).unwrap();
        assert_eq!(number_of_row_affected, 0);
    }
}
