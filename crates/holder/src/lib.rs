//! Platform-neutral holder core. Shells call this crate. The protocol crate
//! does not name a platform API.

use clavis_protocol::did_key_ed25519;
use ed25519_dalek::{Signer, SigningKey};
use rand::rngs::OsRng;

#[derive(Debug, PartialEq, Eq)]
pub struct ExportRefused;

#[derive(Debug, PartialEq, Eq)]
pub struct NoPlatformModule;

pub trait Module {
    fn public_bytes(&self) -> [u8; 32];
    fn sign(&self, message: &[u8]) -> [u8; 64];
    fn try_export(&self) -> Result<Vec<u8>, ExportRefused>;
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