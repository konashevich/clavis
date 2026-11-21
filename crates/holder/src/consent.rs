//! Consent modes for one release.
//!
//! A trusted key whose kinds all match is licensed: one confirmation, and the
//! request must be dynamic. A registered key whose kinds match, with no medical
//! kind, no financial kind, no portrait, and no document number, is ordinary:
//! a static description or a dynamic request, one confirmation. Everything else
//! is heightened: dynamic request, two confirmations.
//!
//! Broken signature, a recipient key the signature does not cover, an expired
//! request, and a static description where licensed or heightened requires a
//! dynamic request are refused before a card. A dynamic nonce builds one
//! presentation.

use std::collections::HashSet;

use clavis_protocol::{
    verify_request_signature, Claim, Request, RequestForm, RequestSignature, SealedPresentation,
};
use clavis_registry::{classify, Category, Operator, Snapshot};
use ed25519_dalek::VerifyingKey;

use crate::PairwiseKey;

/// Clock skew for an injected `now`, matching `clavis_verifier::CLOCK_SKEW_SECONDS`.
pub const CLOCK_SKEW_SECONDS: i64 = 120;

pub const KIND_PERSONAL: &str = "personal";
pub const KIND_FINANCIAL: &str = "financial";
pub const KIND_MEDICAL: &str = "medical";
pub const KIND_EDUCATION: &str = "education";
pub const KIND_PROPERTY: &str = "property";
pub const KIND_RESIDENTIAL: &str = "residential";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsentMode {
    Licensed,
    Ordinary,
    Heightened,
}

impl ConsentMode {
    pub fn confirmations(self) -> u8 {
        match self {
            ConsentMode::Licensed | ConsentMode::Ordinary => 1,
            ConsentMode::Heightened => 2,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    BrokenSignature,
    RecipientNotCovered,
    Expired,
    StaticRequiresDynamic,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum JournalEvent {
    Refusal { request_id: String, reason: Refusal },
    Release { request_id: String, nonce: [u8; 32] },
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReleaseError {
    /// This many confirmations do not release. The card stays up.
    NeedConfirmation {
        got: u8,
        need: u8,
    },
    NonceReused,
    Seal(clavis_protocol::Error),
}

/// Consent card. Only [`Consent::review`] builds one.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Card {
    mode: ConsentMode,
    category: Category,
    operator_name: String,
    request: Request,
    confirmations_required: u8,
    expires_at: i64,
}

impl Card {
    pub fn mode(&self) -> ConsentMode {
        self.mode
    }

    pub fn category(&self) -> Category {
        self.category
    }

    pub fn operator_name(&self) -> &str {
        &self.operator_name
    }

    pub fn confirmations_required(&self) -> u8 {
        self.confirmations_required
    }

    pub fn request(&self) -> &Request {
        &self.request
    }
}

#[derive(Debug, Default)]
pub struct Consent {
    spent: HashSet<[u8; 32]>,
    journal: Vec<JournalEvent>,
}

impl Consent {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn journal(&self) -> &[JournalEvent] {
        &self.journal
    }

    /// Check the signature, the recipient, and expiry, then choose a mode.
    /// A refusal is recorded and no card is returned.
    pub fn review(
        &mut self,
        request: &Request,
        snapshot: Option<&Snapshot>,
        now: i64,
        publisher: &VerifyingKey,
    ) -> Result<Card, Refusal> {
        match verify_request_signature(request) {
            RequestSignature::Covered => {}
            RequestSignature::RecipientNotCovered => {
                return self.refuse(request, Refusal::RecipientNotCovered);
            }
            RequestSignature::Broken => return self.refuse(request, Refusal::BrokenSignature),
        }
        let Some(expires_at) = fresh_expiry(request.expires_at, now) else {
            return self.refuse(request, Refusal::Expired);
        };
        let now_unix = u64::try_from(now).unwrap_or(0);
        let category = classify(snapshot, &request.verifier_did, now_unix, publisher);
        let operator = matching_operator(snapshot, category, &request.verifier_did);
        let mode = select_mode(category, request, operator);
        if request.form != RequestForm::Dynamic && mode != ConsentMode::Ordinary {
            return self.refuse(request, Refusal::StaticRequiresDynamic);
        }
        let operator_name = match operator {
            Some(operator) => operator.name.clone(),
            None => category.label().to_string(),
        };
        Ok(Card {
            mode,
            category,
            operator_name,
            request: request.clone(),
            confirmations_required: mode.confirmations(),
            expires_at,
        })
    }

    /// Build one sealed presentation when `confirmations` meets the card.
    /// A dynamic nonce is stored and does not build a second presentation.
    pub fn release(
        &mut self,
        card: &Card,
        confirmations: u8,
        claims: &[Claim],
        key: &PairwiseKey,
    ) -> Result<SealedPresentation, ReleaseError> {
        if confirmations < card.confirmations_required {
            return Err(ReleaseError::NeedConfirmation {
                got: confirmations,
                need: card.confirmations_required,
            });
        }
        if card.request.form == RequestForm::Dynamic && self.spent.contains(&card.request.nonce) {
            return Err(ReleaseError::NonceReused);
        }
        let sealed = key
            .release_expiring(claims, &card.request, card.expires_at)
            .map_err(ReleaseError::Seal)?;
        if card.request.form == RequestForm::Dynamic {
            self.spent.insert(card.request.nonce);
        }
        self.journal.push(JournalEvent::Release {
            request_id: card.request.id.clone(),
            nonce: card.request.nonce,
        });
        Ok(sealed)
    }

    fn refuse(&mut self, request: &Request, reason: Refusal) -> Result<Card, Refusal> {
        self.journal.push(JournalEvent::Refusal {
            request_id: request.id.clone(),
            reason,
        });
        Err(reason)
    }
}

fn fresh_expiry(expires_at: Option<i64>, now: i64) -> Option<i64> {
    let expires_at = expires_at?;
    let latest = expires_at.checked_add(CLOCK_SKEW_SECONDS)?;
    if now > latest {
        None
    } else {
        Some(expires_at)
    }
}

fn matching_operator<'a>(
    snapshot: Option<&'a Snapshot>,
    category: Category,
    operator_key: &str,
) -> Option<&'a Operator> {
    if !matches!(category, Category::Trusted | Category::Registered) {
        return None;
    }
    snapshot?
        .operators
        .iter()
        .find(|operator| operator.keys.iter().any(|key| key == operator_key))
}

fn select_mode(category: Category, request: &Request, operator: Option<&Operator>) -> ConsentMode {
    let allowed = operator.map(|op| op.kinds.as_slice()).unwrap_or(&[]);
    let kinds_match = request
        .kinds
        .iter()
        .all(|kind| allowed.iter().any(|ok| ok == kind));
    if category == Category::Trusted && kinds_match {
        return ConsentMode::Licensed;
    }
    let sensitive = request.portrait
        || request.document_number
        || request
            .kinds
            .iter()
            .any(|kind| kind == KIND_MEDICAL || kind == KIND_FINANCIAL);
    if category == Category::Registered && kinds_match && !sensitive {
        return ConsentMode::Ordinary;
    }
    ConsentMode::Heightened
}
