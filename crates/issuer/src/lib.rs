use clavis_protocol::{did_key_ed25519, Claim, MerkleTree, Origin};
use ed25519_dalek::{Signer, SigningKey, Verifier, VerifyingKey};
use serde_json::{json, Value};

pub struct Issued {
    pub root: [u8; 32],
    pub issuer_did: String,
    pub signature: [u8; 64],
    pub document: Value,
}

pub fn issue(claims: &[Claim], issuer: &SigningKey) -> Result<Issued, clavis_protocol::Error> {
    let tree = MerkleTree::build(claims)?;
    let issuer_did = did_key_ed25519(&issuer.verifying_key().to_bytes());
    let signature = issuer.sign(&tree.root).to_bytes();
    let mut subject = serde_json::Map::new();
    subject.insert("resourceType".into(), json!("Patient"));
    for claim in tree.claims() {
        subject.insert(claim.path.clone(), json!(claim.value));
    }
    let document = json!({
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential", "FHIRResource"],
        "issuer": issuer_did,
        "credentialSubject": subject,
        "proof": {
            "type": "Ed25519Signature2020",
            "proofPurpose": "assertionMethod",
            "verificationMethod": format!("{issuer_did}#key"),
            "merkleRoot": hex(&tree.root),
            "proofValue": hex(&signature),
            "origin": Origin::IssuerSigned.label(),
        }
    });
    Ok(Issued {
        root: tree.root,
        issuer_did,
        signature,
        document,
    })
}

pub fn self_asserted(claims: &[Claim]) -> Result<Value, clavis_protocol::Error> {
    let tree = MerkleTree::build(claims)?;
    let mut subject = serde_json::Map::new();
    subject.insert("resourceType".into(), json!("Patient"));
    for claim in tree.claims() {
        subject.insert(claim.path.clone(), json!(claim.value));
    }
    Ok(json!({
        "@context": ["https://www.w3.org/2018/credentials/v1"],
        "type": ["VerifiableCredential", "FHIRResource"],
        "credentialSubject": subject,
        "origin": Origin::SelfAsserted.label(),
    }))
}

pub fn verify_issuer(issued: &Issued) -> Result<(), clavis_protocol::Error> {
    let public_key = clavis_protocol::parse_did_key_ed25519(&issued.issuer_did)?;
    let verifying = VerifyingKey::from_bytes(&public_key).map_err(|_| clavis_protocol::Error::Signature)?;
    let signature = ed25519_dalek::Signature::from_bytes(&issued.signature);
    verifying
        .verify(&issued.root, &signature)
        .map_err(|_| clavis_protocol::Error::Signature)
}

fn hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn fhir_and_self_asserted() {
        let claims = vec![
            Claim {
                path: "Patient.name".into(),
                value: "Иванов".into(),
            },
            Claim {
                path: "Patient.allergy".into(),
                value: "пенициллин".into(),
            },
        ];
        let issuer = SigningKey::generate(&mut OsRng);
        let issued = issue(&claims, &issuer).unwrap();
        verify_issuer(&issued).unwrap();
        assert_eq!(
            issued.document["proof"]["origin"],
            Origin::IssuerSigned.label()
        );
        assert_eq!(
            issued.document["credentialSubject"]["Patient.allergy"],
            "пенициллин"
        );

        let own = self_asserted(&claims).unwrap();
        assert!(own.get("proof").is_none());
        assert_eq!(own["origin"], Origin::SelfAsserted.label());
        assert_ne!(own["origin"], issued.document["proof"]["origin"]);
    }
}