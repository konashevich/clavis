//! Platform-neutral CLAVIS objects.
//!
//! Implementation profile: Ed25519, SHA-256 Merkle, X25519 + ChaCha20-Poly1305.
//! Identifiers in this profile are `did:key`. The product DID method stays swappable.

use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand::rngs::OsRng;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use x25519_dalek::{EphemeralSecret, PublicKey, StaticSecret};

pub const PROFILE: &str = "ed25519+sha256-merkle+x25519-chacha20poly1305+did:key";
const PRESENTATION_DOMAIN: &[u8] = b"clavis-presentation-v1";
const AEAD_INFO: &[u8] = b"clavis-presentation-v1";

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    EmptyClaims,
    DuplicatePath,
    Decrypt,
    Encoding,
    Signature,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::EmptyClaims => write!(f, "empty claims"),
            Error::DuplicatePath => write!(f, "duplicate claim path"),
            Error::Decrypt => write!(f, "decrypt failed"),
            Error::Encoding => write!(f, "encoding failed"),
            Error::Signature => write!(f, "signature failed"),
        }
    }
}

impl std::error::Error for Error {}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Origin {
    IssuerSigned,
    SelfAsserted,
}

impl Origin {
    pub fn label(self) -> &'static str {
        match self {
            Origin::IssuerSigned => "подписано эмитентом",
            Origin::SelfAsserted => "внесено человеком",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Claim {
    pub path: String,
    pub value: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Request {
    pub id: String,
    pub verifier_did: String,
    pub verifier_x25519: [u8; 32],
    pub fields: Vec<String>,
    pub nonce: [u8; 32],
    pub purpose: String,
    pub retention: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofStep {
    pub sibling: [u8; 32],
    pub sibling_is_left: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Disclosed {
    pub path: String,
    pub value: Option<String>,
    pub proof: Vec<ProofStep>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Presentation {
    pub request_id: String,
    pub nonce: [u8; 32],
    pub root: [u8; 32],
    pub disclosed: Vec<Disclosed>,
    pub holder_did: String,
    pub signature: Vec<u8>,
    /// Issuer `did:key` when the holder presents an issuer signature.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_did: Option<String>,
    /// Ed25519 signature of that issuer over the Merkle root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issuer_signature: Option<Vec<u8>>,
    /// Credential kind presented for a verifier's local issuer anchor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_kind: Option<String>,
    /// Request expiry, unix seconds. Programs apply their own clock skew.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<i64>,
}

/// Issuer material carried inside an encrypted presentation.
/// The verifier decides origin from these bytes and its own anchor.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CarriedIssuer {
    pub did: String,
    pub signature: Vec<u8>,
    pub kind: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SealedPresentation {
    pub request_id: String,
    pub ephemeral_public: [u8; 32],
    pub aead_nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug)]
pub struct MerkleTree {
    claims: Vec<Claim>,
    leaf_hashes: Vec<[u8; 32]>,
    pub root: [u8; 32],
}

impl MerkleTree {
    pub fn build(claims: &[Claim]) -> Result<Self, Error> {
        if claims.is_empty() {
            return Err(Error::EmptyClaims);
        }
        let mut claims = claims.to_vec();
        claims.sort_by(|a, b| a.path.cmp(&b.path));
        for pair in claims.windows(2) {
            if pair[0].path == pair[1].path {
                return Err(Error::DuplicatePath);
            }
        }
        let leaf_hashes: Vec<[u8; 32]> = claims
            .iter()
            .map(|claim| leaf_hash(&claim.path, &claim.value))
            .collect();
        let root = root_of(&leaf_hashes);
        Ok(Self {
            claims,
            leaf_hashes,
            root,
        })
    }

    pub fn claims(&self) -> &[Claim] {
        &self.claims
    }

    pub fn index_of(&self, path: &str) -> Option<usize> {
        self.claims.iter().position(|claim| claim.path == path)
    }

    pub fn claim(&self, index: usize) -> &Claim {
        &self.claims[index]
    }

    pub fn proof(&self, index: usize) -> Vec<ProofStep> {
        let mut level = self.leaf_hashes.clone();
        let mut idx = index;
        let mut steps = Vec::new();
        while level.len() > 1 {
            if idx % 2 == 1 {
                steps.push(ProofStep {
                    sibling: level[idx - 1],
                    sibling_is_left: true,
                });
            } else if idx + 1 < level.len() {
                steps.push(ProofStep {
                    sibling: level[idx + 1],
                    sibling_is_left: false,
                });
            }
            let mut next = Vec::with_capacity(level.len().div_ceil(2));
            let mut i = 0;
            while i < level.len() {
                if i + 1 < level.len() {
                    next.push(node_hash(&level[i], &level[i + 1]));
                    i += 2;
                } else {
                    next.push(level[i]);
                    i += 1;
                }
            }
            idx /= 2;
            level = next;
        }
        steps
    }

    pub fn verify(path: &str, value: &str, proof: &[ProofStep], root: &[u8; 32]) -> bool {
        let mut hash = leaf_hash(path, value);
        for step in proof {
            hash = if step.sibling_is_left {
                node_hash(&step.sibling, &hash)
            } else {
                node_hash(&hash, &step.sibling)
            };
        }
        hash == *root
    }
}

pub fn did_key_ed25519(public_key: &[u8; 32]) -> String {
    let mut data = Vec::with_capacity(34);
    data.push(0xed);
    data.push(0x01);
    data.extend_from_slice(public_key);
    format!("did:key:z{}", bs58::encode(data).into_string())
}

pub fn parse_did_key_ed25519(did: &str) -> Result<[u8; 32], Error> {
    let rest = did.strip_prefix("did:key:z").ok_or(Error::Encoding)?;
    let bytes = bs58::decode(rest).into_vec().map_err(|_| Error::Encoding)?;
    if bytes.len() != 34 || bytes[0] != 0xed || bytes[1] != 0x01 {
        return Err(Error::Encoding);
    }
    let mut public_key = [0u8; 32];
    public_key.copy_from_slice(&bytes[2..]);
    Ok(public_key)
}

pub fn release(
    claims: &[Claim],
    request: &Request,
    holder: &SigningKey,
) -> Result<SealedPresentation, Error> {
    release_with(claims, request, holder, None, None, None, None)
}

/// [`release`] that also carries an issuer signature, a credential kind, and the
/// request expiry inside the encrypted presentation. Pass `issuer: None` when
/// the holder presents no issuer signature. Those bytes are covered by the
/// holder signature.
pub fn release_carrying(
    claims: &[Claim],
    request: &Request,
    holder: &SigningKey,
    issuer: Option<&CarriedIssuer>,
    expires_at: i64,
) -> Result<SealedPresentation, Error> {
    let (issuer_did, issuer_signature, credential_kind) = match issuer {
        Some(issuer) => (
            Some(issuer.did.clone()),
            Some(issuer.signature.clone()),
            Some(issuer.kind.clone()),
        ),
        None => (None, None, None),
    };
    release_with(
        claims,
        request,
        holder,
        issuer_did,
        issuer_signature,
        credential_kind,
        Some(expires_at),
    )
}

fn release_with(
    claims: &[Claim],
    request: &Request,
    holder: &SigningKey,
    issuer_did: Option<String>,
    issuer_signature: Option<Vec<u8>>,
    credential_kind: Option<String>,
    expires_at: Option<i64>,
) -> Result<SealedPresentation, Error> {
    let tree = MerkleTree::build(claims)?;
    let mut disclosed = Vec::with_capacity(request.fields.len());
    for path in &request.fields {
        if let Some(index) = tree.index_of(path) {
            let claim = tree.claim(index);
            disclosed.push(Disclosed {
                path: claim.path.clone(),
                value: Some(claim.value.clone()),
                proof: tree.proof(index),
            });
        } else {
            disclosed.push(Disclosed {
                path: path.clone(),
                value: None,
                proof: Vec::new(),
            });
        }
    }
    let mut presentation = Presentation {
        request_id: request.id.clone(),
        nonce: request.nonce,
        root: tree.root,
        disclosed,
        holder_did: did_key_ed25519(&holder.verifying_key().to_bytes()),
        signature: Vec::new(),
        issuer_did,
        issuer_signature,
        credential_kind,
        expires_at,
    };
    let message = signing_message(&presentation);
    presentation.signature = holder.sign(&message).to_bytes().to_vec();
    seal(&presentation, &request.verifier_x25519)
}

pub fn verify_holder(presentation: &Presentation) -> Result<(), Error> {
    let public_key = parse_did_key_ed25519(&presentation.holder_did)?;
    let verifying = VerifyingKey::from_bytes(&public_key).map_err(|_| Error::Signature)?;
    let signature = Signature::from_slice(&presentation.signature).map_err(|_| Error::Signature)?;
    verifying
        .verify(&signing_message(presentation), &signature)
        .map_err(|_| Error::Signature)
}

pub fn verify_inclusion(disclosed: &Disclosed, root: &[u8; 32]) -> bool {
    match &disclosed.value {
        Some(value) => MerkleTree::verify(&disclosed.path, value, &disclosed.proof, root),
        None => disclosed.proof.is_empty(),
    }
}

pub fn open(
    sealed: &SealedPresentation,
    verifier_secret: &StaticSecret,
) -> Result<Presentation, Error> {
    let ephemeral = PublicKey::from(sealed.ephemeral_public);
    let shared = verifier_secret.diffie_hellman(&ephemeral);
    let key = derive_key(shared.as_bytes())?;
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let plaintext = cipher
        .decrypt(
            Nonce::from_slice(&sealed.aead_nonce),
            Payload {
                msg: &sealed.ciphertext,
                aad: sealed.request_id.as_bytes(),
            },
        )
        .map_err(|_| Error::Decrypt)?;
    serde_json::from_slice(&plaintext).map_err(|_| Error::Encoding)
}

fn seal(presentation: &Presentation, verifier_x25519: &[u8; 32]) -> Result<SealedPresentation, Error> {
    let verifier_public = PublicKey::from(*verifier_x25519);
    let ephemeral = EphemeralSecret::random_from_rng(OsRng);
    let ephemeral_public = PublicKey::from(&ephemeral);
    let shared = ephemeral.diffie_hellman(&verifier_public);
    let key = derive_key(shared.as_bytes())?;
    let mut aead_nonce = [0u8; 12];
    OsRng.fill_bytes(&mut aead_nonce);
    let cipher = ChaCha20Poly1305::new(Key::from_slice(&key));
    let plaintext = serde_json::to_vec(presentation).map_err(|_| Error::Encoding)?;
    let ciphertext = cipher
        .encrypt(
            Nonce::from_slice(&aead_nonce),
            Payload {
                msg: &plaintext,
                aad: presentation.request_id.as_bytes(),
            },
        )
        .map_err(|_| Error::Decrypt)?;
    Ok(SealedPresentation {
        request_id: presentation.request_id.clone(),
        ephemeral_public: ephemeral_public.to_bytes(),
        aead_nonce,
        ciphertext,
    })
}

fn derive_key(shared: &[u8]) -> Result<[u8; 32], Error> {
    let hk = Hkdf::<Sha256>::new(None, shared);
    let mut okm = [0u8; 32];
    hk.expand(AEAD_INFO, &mut okm).map_err(|_| Error::Decrypt)?;
    Ok(okm)
}

fn signing_message(presentation: &Presentation) -> Vec<u8> {
    let mut message = PRESENTATION_DOMAIN.to_vec();
    message.extend_from_slice(presentation.request_id.as_bytes());
    message.extend_from_slice(&presentation.nonce);
    message.extend_from_slice(&presentation.root);
    message.extend_from_slice(presentation.holder_did.as_bytes());
    for disclosed in &presentation.disclosed {
        message.extend_from_slice(disclosed.path.as_bytes());
        message.push(0);
        match &disclosed.value {
            Some(value) => message.extend_from_slice(value.as_bytes()),
            None => message.push(0xff),
        }
        for step in &disclosed.proof {
            message.extend_from_slice(&step.sibling);
            message.push(u8::from(step.sibling_is_left));
        }
    }
    // Issuer did, issuer signature over the root, credential kind, request expiry.
    message.extend_from_slice(b"carriage");
    bind_bytes(
        &mut message,
        presentation.issuer_did.as_deref().map(|did| did.as_bytes()),
    );
    bind_bytes(&mut message, presentation.issuer_signature.as_deref());
    bind_bytes(
        &mut message,
        presentation
            .credential_kind
            .as_deref()
            .map(|kind| kind.as_bytes()),
    );
    match presentation.expires_at {
        Some(expiry) => {
            message.push(1);
            message.extend_from_slice(&expiry.to_be_bytes());
        }
        None => message.push(0),
    }
    message
}

fn bind_bytes(message: &mut Vec<u8>, value: Option<&[u8]>) {
    match value {
        Some(bytes) => {
            message.push(1);
            message.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
            message.extend_from_slice(bytes);
        }
        None => message.push(0),
    }
}

fn leaf_hash(path: &str, value: &str) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update([0x00]);
    hasher.update(path.as_bytes());
    hasher.update([0x00]);
    hasher.update(value.as_bytes());
    hasher.finalize().into()
}

fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update([0x01]);
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

fn root_of(leaves: &[[u8; 32]]) -> [u8; 32] {
    let mut level = leaves.to_vec();
    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i < level.len() {
            if i + 1 < level.len() {
                next.push(node_hash(&level[i], &level[i + 1]));
                i += 2;
            } else {
                next.push(level[i]);
                i += 1;
            }
        }
        level = next;
    }
    level[0]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn did_key_roundtrip() {
        let signing = SigningKey::generate(&mut OsRng);
        let public_key = signing.verifying_key().to_bytes();
        let did = did_key_ed25519(&public_key);
        assert_eq!(parse_did_key_ed25519(&did).unwrap(), public_key);
    }

    #[test]
    fn merkle_promotes_odd_leaf() {
        let claims = vec![
            Claim { path: "a".into(), value: "1".into() },
            Claim { path: "b".into(), value: "2".into() },
            Claim { path: "c".into(), value: "3".into() },
        ];
        let tree = MerkleTree::build(&claims).unwrap();
        for (index, claim) in ["a", "b", "c"].into_iter().enumerate() {
            let proof = tree.proof(index);
            let value = (index + 1).to_string();
            assert!(MerkleTree::verify(claim, &value, &proof, &tree.root));
        }
    }

    #[test]
    fn origin_labels_differ() {
        assert_ne!(Origin::IssuerSigned.label(), Origin::SelfAsserted.label());
        assert_eq!(Origin::SelfAsserted.label(), "внесено человеком");
        assert_eq!(Origin::IssuerSigned.label(), "подписано эмитентом");
    }
}
