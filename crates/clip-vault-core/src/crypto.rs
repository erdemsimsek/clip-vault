use crate::{ClipEntry, Error};
use aes_gcm::{Aes256Gcm, KeyInit, Nonce, aead::Aead};
use argon2::{Algorithm, Argon2, Params, Version};
use rand_core::{OsRng, RngCore};
use secrecy::{ExposeSecret, SecretBox};
use serde::{Deserialize, Serialize};
use serde_with::{Bytes, serde_as};
use zeroize::{Zeroize, Zeroizing};

/// Argon2id key-derivation parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[allow(clippy::struct_field_names)]
pub struct KdfParams {
    memory_cost: u32,
    time_cost: u32,
    parallel_cost: u32,
}

/// A DEK encrypted by the KEK, stored on disk as part of vault metadata.
#[serde_as]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrappedDek {
    nonce: [u8; 12],
    #[serde_as(as = "Bytes")]
    ciphertext: [u8; 48],
}

/// Encrypted entry with its nonce
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedEntry {
    nonce: [u8; 12],
    ciphertext: Vec<u8>,
}

impl Default for KdfParams {
    fn default() -> Self {
        Self {
            memory_cost: Params::DEFAULT_M_COST,
            time_cost: Params::DEFAULT_T_COST,
            parallel_cost: Params::DEFAULT_P_COST,
        }
    }
}

impl KdfParams {
    /// Constructs validated KDF params, or returns an error if any value is
    /// outside Argon2's accepted range.
    ///
    /// # Errors
    ///
    /// Returns [`Error::Config`] if any of `memory_cost`, `time_cost`, or
    /// `parallel_cost` is outside the range accepted by Argon2id.
    pub fn new(memory_cost: u32, time_cost: u32, parallel_cost: u32) -> Result<Self, Error> {
        if !(Params::MIN_M_COST..=Params::MAX_M_COST).contains(&memory_cost)
            || !(Params::MIN_T_COST..=Params::MAX_T_COST).contains(&time_cost)
            || !(Params::MIN_P_COST..=Params::MAX_P_COST).contains(&parallel_cost)
        {
            return Err(Error::Config("KdfParams not correct".to_string()));
        }
        Ok(Self {
            memory_cost,
            time_cost,
            parallel_cost,
        })
    }
}

/// Derives the Key Encryption Key (KEK) from the user's password.
///
/// Uses Argon2id with the parameters in `params`. The salt is non-secret and
/// must be persisted alongside the wrapped DEK so the same key can be derived
/// on the next session.
///
/// # Errors
///
/// Returns [`Error::Crypto`] if Argon2 rejects the parameters or fails to
/// produce key material.
///
pub fn derive_kek(
    password: &[u8],
    salt: &[u8],
    params: &KdfParams,
) -> Result<SecretBox<[u8; 32]>, Error> {
    let params = argon2::Params::new(
        params.memory_cost,
        params.time_cost,
        params.parallel_cost,
        Some(32usize),
    )
    .map_err(|e| Error::Crypto(Box::new(e)))?;

    let argon = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);

    let mut kek = [0u8; 32];

    argon
        .hash_password_into(password, salt, &mut kek)
        .map_err(|e| Error::Crypto(Box::new(e)))?;

    let key = SecretBox::new(Box::new(kek));

    kek.zeroize();

    Ok(key)
}

/// Generates a fresh Data Encryption Key (DEK) from the OS's secure random
/// source.
///
/// Called once on vault creation. The DEK is then wrapped with the KEK via
/// [`wrap_dek`] and the wrapped form is persisted to disk. The plaintext DEK
/// is held in memory in a [`SecretBox`] while the daemon runs.
#[must_use]
pub fn generate_dek() -> SecretBox<[u8; 32]> {
    let mut key = [0u8; 32];
    OsRng.fill_bytes(&mut key);
    SecretBox::new(Box::new(key))
}

/// Encrypts a Data Encryption Key (DEK) with a Key Encryption Key (KEK).
///
/// Generates a fresh 96-bit nonce and encrypts the DEK with AES-256-GCM.
/// The result is persisted to disk and unwrapped on the next session.
///
/// # Errors
///
/// Returns [`Error::Crypto`] if AES-GCM fails.
pub fn wrap_dek(kek: &SecretBox<[u8; 32]>, dek: &SecretBox<[u8; 32]>) -> Result<WrappedDek, Error> {
    let cipher = Aes256Gcm::new_from_slice(kek.expose_secret())
        .map_err(|_| Error::Crypto("invalid KEK length".into()))?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, dek.expose_secret().as_slice())
        .map_err(|_| Error::Crypto("DEK wrapping failed".into()))?;

    let ciphertext: [u8; 48] = ciphertext // ← Error 1 fix: Vec → [u8;48]
        .try_into()
        .map_err(|_| Error::Crypto("unexpected ciphertext length".into()))?;

    Ok(WrappedDek {
        nonce: nonce_bytes,
        ciphertext,
    })
}

/// Decrypts a wrapped DEK using the KEK.
///
/// # Errors
///
/// - Returns [`Error::WrongPassword`] if decryption fails authentication
/// - Returns [`Error::Crypto`] for other AES-GCM failures.
pub fn unwrap_dek(
    kek: &SecretBox<[u8; 32]>,
    wrapped: &WrappedDek,
) -> Result<SecretBox<[u8; 32]>, Error> {
    let cipher = Aes256Gcm::new_from_slice(kek.expose_secret())
        .map_err(|_| Error::Crypto("invalid KEK length".into()))?;

    let plaintext = Zeroizing::new(
        // ← auto-wipes the transient Vec
        cipher
            .decrypt(
                Nonce::from_slice(&wrapped.nonce), // ← Error 3 fix: [u8;12] → &Nonce
                wrapped.ciphertext.as_slice(),     // ← Error 2 fix: [u8;48] → &[u8]
            )
            .map_err(|_| Error::WrongPassword)?, // auth failure = wrong password
    );

    let mut dek: [u8; 32] = plaintext // ← Error 4 fix: Vec → [u8;32]
        .as_slice()
        .try_into()
        .map_err(|_| Error::Crypto("unexpected DEK length".into()))?;

    let secret = SecretBox::new(Box::new(dek)); // box the [u8;32] (Copy)…
    dek.zeroize(); // …then wipe the stack copy
    Ok(secret)
}

/// Encrypts a clipboard entry with the data encryption key.
///
/// The entry is CBOR-encoded then encrypted with AES-256-GCM using a fresh
/// random nonce. The result includes both the nonce and the ciphertext.///
/// # Errors
///
/// Returns [`Error::Crypto`] if an error raised during the progress.
pub fn encrypt_entry(
    dek: &SecretBox<[u8; 32]>,
    entry: &ClipEntry,
) -> Result<EncryptedEntry, Error> {
    let mut buf = Vec::new();
    ciborium::ser::into_writer(entry, &mut buf).map_err(|e| Error::Crypto(Box::new(e)))?;
    let plaintext = Zeroizing::new(buf);

    let cipher = Aes256Gcm::new_from_slice(dek.expose_secret())
        .map_err(|_| Error::Crypto("Invalid DEK key".into()))?;

    let mut nonce_bytes = [0u8; 12];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_slice())
        .map_err(|_| Error::Crypto("Encrypting entry is failed".into()))?;

    let encrypted_entry = EncryptedEntry {
        nonce: nonce_bytes,
        ciphertext,
    };

    Ok(encrypted_entry)
}

/// Decrypts the entry
///
/// # Errors
///
/// Returns [`Error::Crypto`] if an error raised during the progress.
pub fn decrypt_entry(
    dek: &SecretBox<[u8; 32]>,
    encrypted: &EncryptedEntry,
) -> Result<ClipEntry, Error> {
    let cipher = Aes256Gcm::new_from_slice(dek.expose_secret())
        .map_err(|_| Error::Crypto("Invalid Dek key".into()))?;

    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&encrypted.nonce),
            encrypted.ciphertext.as_slice(),
        )
        .map_err(|_| Error::Crypto("Decrypting failed".into()))?;

    let entry =
        ciborium::de::from_reader(plaintext.as_slice()).map_err(|e| Error::Crypto(Box::new(e)))?;

    Ok(entry)
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {

    use super::*;
    use crate::{EntryContent, Sensitivity};
    use proptest::prelude::*;

    fn text_entry(text: impl Into<String>) -> ClipEntry {
        let entry: ClipEntry = ClipEntry::new(
            EntryContent::Text(text.into()),
            Sensitivity::Normal,
            vec!["text/plain".into()],
        );
        entry
    }

    proptest! {
        #[test]
        fn entry_round_trip(text in ".*") {
            let dek = generate_dek();
            let entry = text_entry(text);
            let cipher_text = encrypt_entry(&dek, &entry);
            let decrypted = decrypt_entry(&dek, &cipher_text.unwrap()).unwrap();
            prop_assert_eq!(entry, decrypted);
        }
    }

    #[test]
    fn wrapped_dek_round_trip() {
        let password = "password";
        let kdfparams = KdfParams::default();

        let kek = derive_kek(password.as_bytes(), password.as_bytes(), &kdfparams);
        let dek = generate_dek();

        let wrap_dek = wrap_dek(kek.as_ref().unwrap(), &dek).unwrap();
        let unwrap_dek = unwrap_dek(kek.as_ref().unwrap(), &wrap_dek).unwrap();

        assert_eq!(dek.expose_secret(), unwrap_dek.expose_secret());
    }

    #[test]
    fn fresh_nonce_per_entry() {
        let dek = generate_dek();
        let entry = text_entry("same");

        let first_cipher = encrypt_entry(&dek, &entry).unwrap();
        let second_cipher = encrypt_entry(&dek, &entry).unwrap();

        assert_ne!(first_cipher.nonce, second_cipher.nonce);
        assert_ne!(first_cipher.ciphertext, second_cipher.ciphertext);
    }

    #[test]
    fn debug_does_not_leak_key() {
        let debug = format!("{:?}", generate_dek());
        assert!(
            debug.contains("REDACTED"),
            "should be redacted, got: {debug}"
        );
    }

    #[test]
    fn unwrap_with_wrong_kek_rejected() {
        let kek_first = derive_kek(b"password1", b"password123", &KdfParams::default());
        let kek_second = derive_kek(b"password2", b"password234", &KdfParams::default());

        let dek = generate_dek();

        let wrap_dek = wrap_dek(kek_first.as_ref().unwrap(), &dek);
        let unwrap_dek = unwrap_dek(kek_second.as_ref().unwrap(), &wrap_dek.unwrap());

        assert!(matches!(unwrap_dek, Err(Error::WrongPassword)));
    }

    #[test]
    fn tampered_wrapped_dek_rejected() {
        let password = "password";
        let kdfparams = KdfParams::default();

        let kek = derive_kek(password.as_bytes(), password.as_bytes(), &kdfparams);
        let dek = generate_dek();

        let mut wrap_dek = wrap_dek(kek.as_ref().unwrap(), &dek).unwrap();

        wrap_dek.ciphertext[0] ^= 1;

        let unwrap_dek = unwrap_dek(kek.as_ref().unwrap(), &wrap_dek);

        assert!(unwrap_dek.is_err());
    }

    #[test]
    fn derive_kek_is_deterministic() {
        let kek_first = derive_kek(b"password", b"abcdefgh", &KdfParams::default());
        let kek_second = derive_kek(b"password", b"abcdefgh", &KdfParams::default());

        assert_eq!(
            kek_first.unwrap().expose_secret(),
            kek_second.unwrap().expose_secret()
        );
    }

    #[test]
    fn derive_kek_salt_changes_key() {
        let kek_first = derive_kek(b"password", b"abcdefgh", &KdfParams::default());
        let kek_second = derive_kek(b"password", b"abcdefghijklm", &KdfParams::default());

        assert_ne!(
            kek_first.unwrap().expose_secret(),
            kek_second.unwrap().expose_secret()
        );
    }

    #[test]
    fn kdf_params_rejects_out_of_range() {
        let param = KdfParams::new(0, 0, 0);
        assert!(param.is_err());
    }
}
