//! Journal of requests and the statements that later arrive.
//!
//! A row stores the request, including its purpose and retention. A deletion
//! or continued-storage statement is stored on that row only when the key
//! named by the request signs it and the statement names that request id.
//! The journal does not read a verifier database. Silence is not deletion.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};

use clavis_protocol::{parse_did_key_ed25519, Request};

const STATEMENT_DOMAIN: &[u8] = b"clavis-journal-statement-v1";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StatementKind {
    Deletion,
    ContinuedStorage { retention: String, reason: String },
}

/// A statement that arrived. An empty signature is unsigned and is not stored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArrivedStatement {
    pub request_id: String,
    pub kind: StatementKind,
    pub signature: Vec<u8>,
}

impl ArrivedStatement {
    pub fn signed(request_id: impl Into<String>, kind: StatementKind, key: &SigningKey) -> Self {
        let request_id = request_id.into();
        let signature = key
            .sign(&statement_message(&request_id, &kind))
            .to_bytes()
            .to_vec();
        Self {
            request_id,
            kind,
            signature,
        }
    }

    pub fn unsigned(request_id: impl Into<String>, kind: StatementKind) -> Self {
        Self {
            request_id: request_id.into(),
            kind,
            signature: Vec::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StoredStatement {
    pub kind: StatementKind,
    pub signature: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct JournalRow {
    pub request: Request,
    pub statement: Option<StoredStatement>,
}

impl JournalRow {
    /// No signed statement has been stored on this row.
    pub fn is_open(&self) -> bool {
        self.statement.is_none()
    }

    /// Deletion is only a stored deletion statement. Silence is not deletion.
    pub fn is_deletion(&self) -> bool {
        matches!(
            &self.statement,
            Some(StoredStatement {
                kind: StatementKind::Deletion,
                ..
            })
        )
    }

    /// New retention and the named reason, when continued storage was stored.
    pub fn continued_storage(&self) -> Option<(&str, &str)> {
        match &self.statement {
            Some(StoredStatement {
                kind: StatementKind::ContinuedStorage { retention, reason },
                ..
            }) => Some((retention.as_str(), reason.as_str())),
            _ => None,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum StatementError {
    /// No row has this request id, so no row is closed.
    UnknownRequest,
    /// The statement carried no signature.
    Unsigned,
    /// The signature is not from the key named by that request.
    BadSignature,
}

#[derive(Debug, PartialEq, Eq)]
pub struct JournalParseError;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Journal {
    rows: Vec<JournalRow>,
}

impl Journal {
    pub fn new() -> Self {
        Self { rows: Vec::new() }
    }

    pub fn record_request(&mut self, request: Request) {
        if self.rows.iter().any(|row| row.request.id == request.id) {
            return;
        }
        self.rows.push(JournalRow {
            request,
            statement: None,
        });
    }

    pub fn row(&self, request_id: &str) -> Option<&JournalRow> {
        self.rows.iter().find(|row| row.request.id == request_id)
    }

    /// Store `arrived` on the row it names. Any other row is left as it is.
    /// The signature must be from the Ed25519 key named by that row's `verifier_did`.
    #[must_use]
    pub fn record_statement(&mut self, arrived: &ArrivedStatement) -> Result<(), StatementError> {
        let index = self
            .rows
            .iter()
            .position(|row| row.request.id == arrived.request_id)
            .ok_or(StatementError::UnknownRequest)?;
        if arrived.signature.is_empty() {
            return Err(StatementError::Unsigned);
        }
        let request_key = parse_did_key_ed25519(&self.rows[index].request.verifier_did)
            .map_err(|_| StatementError::BadSignature)?;
        let verifying =
            VerifyingKey::from_bytes(&request_key).map_err(|_| StatementError::BadSignature)?;
        let signature =
            Signature::from_slice(&arrived.signature).map_err(|_| StatementError::BadSignature)?;
        verifying
            .verify(
                &statement_message(&arrived.request_id, &arrived.kind),
                &signature,
            )
            .map_err(|_| StatementError::BadSignature)?;
        self.rows[index].statement = Some(StoredStatement {
            kind: arrived.kind.clone(),
            signature: arrived.signature.clone(),
        });
        Ok(())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        serde_json::to_vec(self).expect("journal serializes")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, JournalParseError> {
        serde_json::from_slice(bytes).map_err(|_| JournalParseError)
    }
}

fn statement_message(request_id: &str, kind: &StatementKind) -> Vec<u8> {
    let mut message = STATEMENT_DOMAIN.to_vec();
    message.push(0);
    message.extend_from_slice(request_id.as_bytes());
    message.push(0);
    match kind {
        StatementKind::Deletion => message.push(1),
        StatementKind::ContinuedStorage { retention, reason } => {
            message.push(2);
            message.extend_from_slice(&(retention.len() as u64).to_be_bytes());
            message.extend_from_slice(retention.as_bytes());
            message.extend_from_slice(&(reason.len() as u64).to_be_bytes());
            message.extend_from_slice(reason.as_bytes());
        }
    }
    message
}
