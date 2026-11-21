//! Platform-neutral holder core. Shells call this crate. The protocol crate
//! does not name a platform API.

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use clavis_protocol::{did_key_ed25519, Claim, Request, SealedPresentation};
use ed25519_dalek::{Signer, SigningKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use sha2::Sha256;

const DEVICE_WRAP_INFO: &[u8] = b"clavis-device-wrap-v1";
const RECOVERY_INFO: &[u8] = b"clavis-recovery-v1";

#[derive(Debug, PartialEq, Eq)]
pub struct ExportRefused;

#[derive(Debug, PartialEq, Eq)]
pub struct NoPlatformModule;

#[derive(Debug, PartialEq, Eq)]
pub struct UnwrapFailed;

/// Recovery bundle: the index, the journal, and one container each have their own data key.
/// A vault with many containers is a [`Store`]. Passphrase recovery still wraps this bundle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataKeys {
    pub index: [u8; 32],
    pub journal: [u8; 32],
    pub container: [u8; 32],
}

impl DataKeys {
    pub fn generate() -> Self {
        Self {
            index: generate_data_key(),
            journal: generate_data_key(),
            container: generate_data_key(),
        }
    }
}

pub fn generate_data_key() -> [u8; 32] {
    random_bytes()
}

/// Nonce and ciphertext of one 32-byte data key. The wrapping secret is not stored.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataKeyWrap {
    pub nonce: [u8; 12],
    pub ciphertext: [u8; 48],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DataKeyWraps {
    pub index: DataKeyWrap,
    pub journal: DataKeyWrap,
    pub container: DataKeyWrap,
}

pub trait Module {
    fn public_bytes(&self) -> [u8; 32];
    fn sign(&self, message: &[u8]) -> [u8; 64];
    fn try_export(&self) -> Result<Vec<u8>, ExportRefused>;
    fn wrap(&self, data_key: &[u8; 32]) -> DataKeyWrap;
    fn unwrap(&self, wrap: &DataKeyWrap) -> Result<[u8; 32], UnwrapFailed>;
}

pub struct TestModule {
    signing: SigningKey,
}

impl TestModule {
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
        }
    }

    fn device_wrap_key(&self) -> [u8; 32] {
        let seed = self.signing.to_bytes();
        hkdf_sha256(&seed, DEVICE_WRAP_INFO)
    }
}

impl Module for TestModule {
    fn public_bytes(&self) -> [u8; 32] {
        self.signing.verifying_key().to_bytes()
    }

    fn sign(&self, message: &[u8]) -> [u8; 64] {
        self.signing.sign(message).to_bytes()
    }

    fn try_export(&self) -> Result<Vec<u8>, ExportRefused> {
        Err(ExportRefused)
    }

    fn wrap(&self, data_key: &[u8; 32]) -> DataKeyWrap {
        let key = self.device_wrap_key();
        seal(&key, data_key)
    }

    fn unwrap(&self, wrap: &DataKeyWrap) -> Result<[u8; 32], UnwrapFailed> {
        let key = self.device_wrap_key();
        open(&key, wrap)
    }
}

pub fn boot(platform_module_present: bool) -> Result<(), NoPlatformModule> {
    if platform_module_present {
        Ok(())
    } else {
        Err(NoPlatformModule)
    }
}

pub struct PairwiseKey {
    signing: SigningKey,
}

impl PairwiseKey {
    pub fn generate() -> Self {
        Self {
            signing: SigningKey::generate(&mut OsRng),
        }
    }

    pub fn did(&self) -> String {
        did_key_ed25519(&self.signing.verifying_key().to_bytes())
    }

    pub fn try_export(&self) -> Result<Vec<u8>, ExportRefused> {
        Err(ExportRefused)
    }

    /// Seal one presentation with this pairwise key. The signing key stays here.
    pub fn release(
        &self,
        claims: &[Claim],
        request: &Request,
    ) -> Result<SealedPresentation, clavis_protocol::Error> {
        clavis_protocol::release(claims, request, &self.signing)
    }
}

pub fn wrap_data_keys(module: &impl Module, keys: &DataKeys) -> DataKeyWraps {
    DataKeyWraps {
        index: module.wrap(&keys.index),
        journal: module.wrap(&keys.journal),
        container: module.wrap(&keys.container),
    }
}

pub fn unwrap_data_keys(
    module: &impl Module,
    wraps: &DataKeyWraps,
) -> Result<DataKeys, UnwrapFailed> {
    Ok(DataKeys {
        index: module.unwrap(&wraps.index)?,
        journal: module.unwrap(&wraps.journal)?,
        container: module.unwrap(&wraps.container)?,
    })
}

pub fn wrap_with_passphrase(passphrase: &[u8], keys: &DataKeys) -> DataKeyWraps {
    let key = hkdf_sha256(passphrase, RECOVERY_INFO);
    DataKeyWraps {
        index: seal(&key, &keys.index),
        journal: seal(&key, &keys.journal),
        container: seal(&key, &keys.container),
    }
}

pub fn unwrap_with_passphrase(
    passphrase: &[u8],
    wraps: &DataKeyWraps,
) -> Result<DataKeys, UnwrapFailed> {
    let key = hkdf_sha256(passphrase, RECOVERY_INFO);
    Ok(DataKeys {
        index: open(&key, &wraps.index)?,
        journal: open(&key, &wraps.journal)?,
        container: open(&key, &wraps.container)?,
    })
}

/// Open the passphrase wraps and seal the same data keys to `module`.
/// The previous device key is not an input and is not rebuilt.
pub fn rewrap_with_passphrase(
    module: &impl Module,
    passphrase: &[u8],
    recovery: &DataKeyWraps,
) -> Result<DataKeyWraps, UnwrapFailed> {
    let keys = unwrap_with_passphrase(passphrase, recovery)?;
    Ok(wrap_data_keys(module, &keys))
}

mod store;

pub use store::{
    open_body, open_index, open_journal, open_release, seal_store, Container, ContainerId,
    OpenError, OpenedContainer, SealedBody, SealedContainer, SealedStore, Store,
};

fn random_bytes() -> [u8; 32] {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    bytes
}

fn hkdf_sha256(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, ikm);
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm).expect("32-byte HKDF output");
    okm
}

pub(crate) struct SealedBytes {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

pub(crate) fn seal_bytes(key: &[u8; 32], plaintext: &[u8]) -> SealedBytes {
    let mut nonce = [0u8; 12];
    OsRng.fill_bytes(&mut nonce);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    let ciphertext = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .expect("seal");
    SealedBytes { nonce, ciphertext }
}

pub(crate) fn open_bytes(
    key: &[u8; 32],
    nonce: &[u8; 12],
    ciphertext: &[u8],
) -> Result<Vec<u8>, UnwrapFailed> {
    let cipher = ChaCha20Poly1305::new(Key::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| UnwrapFailed)
}

fn seal(key: &[u8; 32], data_key: &[u8; 32]) -> DataKeyWrap {
    let sealed = seal_bytes(key, data_key);
    DataKeyWrap {
        nonce: sealed.nonce,
        ciphertext: sealed
            .ciphertext
            .try_into()
            .expect("ChaCha20-Poly1305 adds a 16-byte tag"),
    }
}

fn open(key: &[u8; 32], wrap: &DataKeyWrap) -> Result<[u8; 32], UnwrapFailed> {
    let plain = open_bytes(key, &wrap.nonce, &wrap.ciphertext)?;
    plain.try_into().map_err(|_| UnwrapFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn boot_and_keys() {
        assert_eq!(boot(false), Err(NoPlatformModule));
        assert_eq!(boot(true), Ok(()));

        let device = TestModule::generate();
        assert_eq!(device.try_export(), Err(ExportRefused));
        let signature = device.sign(b"release");
        assert_eq!(signature.len(), 64);

        let first = PairwiseKey::generate();
        let second = PairwiseKey::generate();
        assert_ne!(first.did(), second.did());
        assert!(first.try_export().is_err());
        assert_ne!(first.did(), did_key_ed25519(&device.public_bytes()));
    }
}
