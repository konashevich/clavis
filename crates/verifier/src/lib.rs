//! Linux verifier.
//!
//! Origin is decided from the issuer bytes inside the presentation and from
//! the local issuer anchor. A holder-supplied origin string is not read.

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
    Inclusion,
    IssuerSignature,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Open(err) => write!(f, "{err}"),
            Error::HolderSignature => write!(f, "holder signature failed"),
            Error::Freshness => write!(f, "freshness failed"),
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

/// Decrypt with the verifier secret, then check freshness, inclusion, and the
/// local issuer anchor. `now` is injected unix seconds. This path does not
/// read a wall clock.
pub fn accept(
    sealed: &SealedPresentation,
    verifier_secret: &StaticSecret,
    anchor: &IssuerAnchor,
    expected_nonce: &[u8; 32],
    now: i64,
) -> Result<Accepted, Error> {
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
