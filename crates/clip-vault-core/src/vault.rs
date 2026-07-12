use crate::{
    ClipEntry, ContentKind, EncryptedEntry, EntryContent, EntryId, EntryMeta, Error, KdfParams,
    Storage, WrappedDek, decrypt_entry, derive_kek, encrypt_entry, generate_dek, unwrap_dek,
    wrap_dek,
};
use rand_core::{OsRng, RngCore};
use secrecy::SecretBox;
use serde::{Deserialize, Serialize};

/// Vault keeps the dek key in plaintext and DB connection.
pub struct Vault {
    store: Storage,
    dek: SecretBox<[u8; 32]>,
}

#[derive(Serialize, Deserialize)]
/// Vault metadata
pub struct VaultMeta {
    salt: [u8; 16],
    wrapped_dek: WrappedDek,
    kdf: KdfParams,
}

impl VaultMeta {
    /// Converts `VaultMeta` into byte array.
    fn to_bytes(&self) -> crate::Result<Vec<u8>> {
        let mut buf = Vec::new();
        ciborium::ser::into_writer(self, &mut buf).map_err(|e| Error::Crypto(Box::new(e)))?;
        Ok(buf)
    }
}

impl Vault {
    /// Creates the vault.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] or [`Error::Storage`] if an error raised during the progress.
    pub fn create(password: &[u8]) -> crate::Result<Self> {
        Self::create_with(Storage::open()?, password)
    }

    /// Unlock the vault.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] or [`Error::Storage`] if an error raised during the progress.
    pub fn unlock(password: &[u8]) -> crate::Result<Self> {
        Self::unlock_with(Storage::open()?, password)
    }

    /// Creates the vault for unit testing or internal use.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] or [`Error::Storage`] if an error raised during the progress.
    pub(crate) fn create_with(store: Storage, password: &[u8]) -> crate::Result<Self> {
        let kdf = KdfParams::default();
        let mut salt = [0; 16];
        OsRng.fill_bytes(&mut salt);

        let dek = generate_dek();
        let kek = derive_kek(password, &salt, &kdf)?;
        let wrapped_dek = wrap_dek(&kek, &dek)?;

        let metadata = VaultMeta {
            salt,
            wrapped_dek,
            kdf,
        };

        let metadata_blob = metadata.to_bytes()?;

        store.save_vault(&metadata_blob)?;

        Ok(Self { store, dek })
    }

    /// Unlocks the vaults for unit testing or internal use.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] or [`Error::Storage`] if an error raised during the progress.
    pub(crate) fn unlock_with(store: Storage, password: &[u8]) -> crate::Result<Self> {
        let vault = store.load_vault()?.ok_or(Error::VaultLocked)?;
        let vault_meta: VaultMeta =
            ciborium::de::from_reader(vault.as_slice()).map_err(|e| Error::Crypto(Box::new(e)))?;
        let kek = derive_kek(password, &vault_meta.salt, &vault_meta.kdf)?;
        let dek = unwrap_dek(&kek, &vault_meta.wrapped_dek)?;

        Ok(Self { store, dek })
    }

    /// Adds a new entry the vault.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] [`Error::Storage`] if an error raised during the progress.
    pub fn add(&self, entry: &ClipEntry) -> crate::Result<()> {
        let content_kind: ContentKind = {
            match entry.get_entry_content() {
                EntryContent::Text(_) => ContentKind::Text,
                EntryContent::Image(_) => ContentKind::Image,
                EntryContent::Binary(_) => ContentKind::Binary,
            }
        };

        let metadata: EntryMeta = EntryMeta {
            created_at: entry.get_entry_created_at().timestamp_millis(),
            expires_at: entry.get_entry_expires_at().map(|s| s.timestamp_millis()),
            pinned: entry.get_entry_pinned(),
            times_pasted: entry.get_entry_times_pasted().to_owned().into(),
            content_kind,
        };

        let encrypted = encrypt_entry(&self.dek, entry)?;
        let mut blob = Vec::new();
        ciborium::ser::into_writer(&encrypted, &mut blob) // serialize the EncryptedEntry → bytes
            .map_err(|e| Error::Crypto(Box::new(e)))?;
        self.store.add(*entry.get_entry_id(), &blob, &metadata)
    }

    /// Fetchs the entries from the vault.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Crypto`] or [`Error::Storage`] if an error raised during the progress.
    pub fn list(&self, after: Option<EntryId>, limit: i64) -> crate::Result<Vec<ClipEntry>> {
        let stored_entry = self.store.list(after, limit)?;
        let mut clip_entry = Vec::<ClipEntry>::new();
        for elem in &stored_entry {
            let encrypted_entry: EncryptedEntry = ciborium::de::from_reader(elem.blob.as_slice())
                .map_err(|e| Error::Crypto(Box::new(e)))?;
            let decrypted_entry = decrypt_entry(&self.dek, &encrypted_entry)?;
            clip_entry.push(decrypted_entry);
        }

        Ok(clip_entry)
    }

    /// Delets the entry from database.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if an error raised during the progress.
    pub fn delete(&self, ids: &[EntryId]) -> crate::Result<usize> {
        self.store.delete(ids)
    }

    /// Delete the expired entries from database.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if an error raised during the progress.
    pub fn purge_expired(&self, now: i64) -> crate::Result<usize> {
        self.store.purge_expired(now)
    }
    /// Pin the given entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if an error raised during the progress.
    pub fn set_pin(&self, id: &EntryId, pinned: bool) -> crate::Result<usize> {
        self.store.set_pin(id, pinned)
    }
    /// Increment number of pasted for the given entry.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Storage`] if an error raised during the progress.
    pub fn mark_pasted(&self, id: &EntryId) -> crate::Result<usize> {
        self.store.mark_pasted(id)
    }

    /// Test-only escape hatch: drop the vault (zeroizing the DEK) but keep the
    /// store, so a second `Vault` can be opened over the same in-memory data.
    #[cfg(test)]
    fn into_store(self) -> Storage {
        self.store
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use super::*;
    use crate::Sensitivity;

    fn test_entry() -> ClipEntry {
        ClipEntry::new(
            EntryContent::Text("hello world".to_string()),
            Sensitivity::Normal,
            vec!["text/plain".into()],
        )
    }

    #[test]
    fn add_then_list_round_trips() {
        let vault = Vault::create_with(Storage::in_memory().unwrap(), b"password").unwrap();
        let entry = test_entry();

        vault.add(&entry).unwrap();
        let entries = vault.list(None, 10).unwrap();

        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], entry);
    }

    #[test]
    fn unlock_fresh_store_errors() {
        let result = Vault::unlock_with(Storage::in_memory().unwrap(), b"password");

        assert!(matches!(result, Err(Error::VaultLocked)));
    }

    #[test]
    fn unlock_wrong_password_rejected() {
        let vault = Vault::create_with(Storage::in_memory().unwrap(), b"correct").unwrap();

        let store = vault.into_store();
        let result = Vault::unlock_with(store, b"wrong");

        assert!(matches!(result, Err(Error::WrongPassword)));
    }

    #[test]
    fn reopened_vault_decrypts_old_entries() {
        let vault = Vault::create_with(Storage::in_memory().unwrap(), b"password").unwrap();
        let entry = test_entry();
        vault.add(&entry).unwrap();

        // "restart": first vault drops (DEK zeroized), same store reopened fresh.
        let store = vault.into_store();
        let vault = Vault::unlock_with(store, b"password").unwrap();

        let entries = vault.list(None, 10).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0], entry);
    }
}
