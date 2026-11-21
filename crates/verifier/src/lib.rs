//! Linux verifier.
//!
//! Origin is decided from the issuer bytes inside the presentation and from
//! the local issuer anchor. A holder-supplied origin string is not read.

use std::collections::{HashMap, HashSet};

use clavis_protocol::{Presentation, SealedPresentation};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use x25519_dalek::StaticSecret;

/// Clock skew programs allow when a test or caller injects `now`.
pub const CLOCK_SKEW_SECONDS: i64 = 120;

const ORIGIN_ACCEPTED: &str = "подпись эмитента принята";
const ORIGIN_UNRECOGNIZED: &str = "подпись без признанного эмитента";
const ORIGIN_SELF: &str = "внесено человеком";

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Open(clavis_protocol::Error),
    HolderSignature,
    Freshness,
    /// This nonce was already accepted for an open request.
    Replay,
    Inclusion,
    IssuerSignature,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Open(err) => write!(f, "{err}"),
            Error::HolderSignature => write!(f, "holder signature failed"),
            Error::Freshness => write!(f, "freshness failed"),
            Error::Replay => write!(f, "replay rejected"),
            Error::Inclusion => write!(f, "inclusion failed"),
            Error::IssuerSignature => write!(f, "issuer signature failed"),
        }
    }
}

impl std::error::Error for Error {}

/// Local clinic anchor. This is verifier configuration, not the operator registry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IssuerAnchor {
    pub name: String,
    pub issuer_did: String,
    pub kinds: Vec<String>,
}

#[derive(Debug, PartialEq, Eq)]
pub struct Accepted {
    pub presentation: Presentation,
    /// One of the verifier origin labels, computed here.
    pub origin: String,
    /// Anchor name, set only when that anchor accepted the issuer signature.
    pub anchor_name: Option<String>,
}

pub fn open_presentation(
    sealed: &SealedPresentation,
    verifier_secret: &StaticSecret,
) -> Result<Presentation, clavis_protocol::Error> {
    clavis_protocol::open(sealed, verifier_secret)
}

/// Nonces this verifier has issued and not yet accepted.
///
/// [`accept`] rejects a nonce that is not still open, a request that has
/// expired, and a nonce already accepted on this set.
#[derive(Clone, Debug, Default)]
pub struct OpenRequests {
    open: HashMap<[u8; 32], i64>,
    spent: HashSet<[u8; 32]>,
}

impl OpenRequests {
    pub fn new() -> Self {
        Self::default()
    }

    /// Remember one request. A spent nonce stays spent.
    pub fn insert(&mut self, nonce: [u8; 32], expires_at: i64) {
        if self.spent.contains(&nonce) {
            return;
        }
        self.open.insert(nonce, expires_at);
    }

    fn screen(&self, nonce: &[u8; 32], now: i64) -> Result<(), Error> {
        if self.spent.contains(nonce) {
            return Err(Error::Replay);
        }
        let Some(&expires_at) = self.open.get(nonce) else {
            return Err(Error::Freshness);
        };
        let Some(latest) = expires_at.checked_add(CLOCK_SKEW_SECONDS) else {
            return Err(Error::Freshness);
        };
        if now > latest {
            return Err(Error::Freshness);
        }
        Ok(())
    }

    fn spend(&mut self, nonce: &[u8; 32]) {
        self.open.remove(nonce);
        self.spent.insert(*nonce);
    }
}

/// Decrypt with the verifier secret, then check that `expected_nonce` is a
/// still-open request, that the request and the presentation have not expired,
/// and that this nonce was not already accepted. `now` is injected unix seconds.
/// This path does not read a wall clock.
pub fn accept(
    sealed: &SealedPresentation,
    verifier_secret: &StaticSecret,
    anchor: &IssuerAnchor,
    expected_nonce: &[u8; 32],
    now: i64,
    open_requests: &mut OpenRequests,
) -> Result<Accepted, Error> {
    open_requests.screen(expected_nonce, now)?;
    let presentation = open_presentation(sealed, verifier_secret).map_err(Error::Open)?;
    clavis_protocol::verify_holder(&presentation).map_err(|_| Error::HolderSignature)?;
    if !fresh(&presentation, expected_nonce, now) {
        return Err(Error::Freshness);
    }
    if !presentation
        .disclosed
        .iter()
        .all(|disclosed| clavis_protocol::verify_inclusion(disclosed, &presentation.root))
    {
        return Err(Error::Inclusion);
    }
    let (origin, anchor_name) = decide_origin(&presentation, anchor)?;
    open_requests.spend(expected_nonce);
    Ok(Accepted {
        presentation,
        origin: origin.to_string(),
        anchor_name,
    })
}

fn fresh(presentation: &Presentation, expected_nonce: &[u8; 32], now: i64) -> bool {
    if presentation.nonce != *expected_nonce {
        return false;
    }
    let Some(expires_at) = presentation.expires_at else {
        return false;
    };
    let Some(latest) = expires_at.checked_add(CLOCK_SKEW_SECONDS) else {
        return false;
    };
    now <= latest
}

fn decide_origin(
    presentation: &Presentation,
    anchor: &IssuerAnchor,
) -> Result<(&'static str, Option<String>), Error> {
    if presentation.issuer_signature.is_none() {
        return Ok((ORIGIN_SELF, None));
    }
    verify_presented_issuer(presentation)?;
    let did_ok = presentation.issuer_did.as_deref() == Some(anchor.issuer_did.as_str());
    let kind_ok = presentation
        .credential_kind
        .as_ref()
        .is_some_and(|kind| anchor.kinds.iter().any(|allowed| allowed == kind));
    if did_ok && kind_ok {
        Ok((ORIGIN_ACCEPTED, Some(anchor.name.clone())))
    } else {
        Ok((ORIGIN_UNRECOGNIZED, None))
    }
}

fn verify_presented_issuer(presentation: &Presentation) -> Result<(), Error> {
    let signature_bytes = presentation
        .issuer_signature
        .as_deref()
        .ok_or(Error::IssuerSignature)?;
    let did = presentation
        .issuer_did
        .as_deref()
        .ok_or(Error::IssuerSignature)?;
    let public_key =
        clavis_protocol::parse_did_key_ed25519(did).map_err(|_| Error::IssuerSignature)?;
    let verifying = VerifyingKey::from_bytes(&public_key).map_err(|_| Error::IssuerSignature)?;
    let signature = Signature::from_slice(signature_bytes).map_err(|_| Error::IssuerSignature)?;
    verifying
        .verify(&presentation.root, &signature)
        .map_err(|_| Error::IssuerSignature)
}
