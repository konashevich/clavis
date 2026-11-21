//! Windows holder shell.
//!
//! Builds the same sealed presentation as the other holders: one requested
//! field, encrypted to the verifier. The device key stays behind the test
//! module. The pairwise presentation key is not exported. The Windows binary
//! itself is built on MyNUC; this crate is the shell.

use clavis_holder::{Module, PairwiseKey, TestModule};
use clavis_protocol::{Claim, Request, SealedPresentation};

pub fn shell_name() -> &'static str {
    "windows"
}

/// The shell starts only when a platform module is present.
/// The binary passes `true` and then uses the test module.
pub fn boot(platform_module_present: bool) -> Result<(), clavis_holder::NoPlatformModule> {
    clavis_holder::boot(platform_module_present)
}

/// In-process Windows holder. One call to [`Holder::release`] seals one presentation.
pub struct Holder {
    module: TestModule,
    pairwise: PairwiseKey,
    claims: Vec<Claim>,
}

impl Holder {
    /// Boot with the test module, the same gate `main` uses (`boot(true)`).
    pub fn start(claims: Vec<Claim>) -> Result<Self, clavis_holder::NoPlatformModule> {
        boot(true)?;
        Ok(Self {
            module: TestModule::generate(),
            pairwise: PairwiseKey::generate(),
            claims,
        })
    }

    /// Seal one presentation for this request. Unrequested claims stay out of it.
    pub fn release(&self, request: &Request) -> Result<SealedPresentation, clavis_protocol::Error> {
        self.pairwise.release(&self.claims, request)
    }

    pub fn device_did(&self) -> String {
        clavis_protocol::did_key_ed25519(&self.module.public_bytes())
    }

    pub fn pairwise_did(&self) -> String {
        self.pairwise.did()
    }

    /// Device key and pairwise key both stay inside. Export stays refused.
    pub fn keys_remain_inside(&self) -> bool {
        self.module.try_export().is_err() && self.pairwise.try_export().is_err()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_is_windows() {
        assert_eq!(shell_name(), "windows");
    }
}
