use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

pub const UNCHECKED_LABEL: &str = "категория не проверена";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Operator {
    pub name: String,
    pub category: String,
    pub kinds: Vec<String>,
    pub keys: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub operators: Vec<Operator>,
    pub expires_unix: u64,
    pub publisher_did: String,
    pub signature: [u8; 64],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Category {
    Trusted,
    Registered,
    Unregistered,
    Unchecked,
}

impl Category {
    pub fn label(self) -> &'static str {
        match self {
            Category::Trusted => "доверенный",
            Category::Registered => "зарегистрированный",
            Category::Unregistered => "незарегистрированный",
            Category::Unchecked => UNCHECKED_LABEL,
        }
    }
}

pub fn sign_snapshot(
    operators: Vec<Operator>,
    expires_unix: u64,
    publisher: &SigningKey,
) -> Snapshot {
    let publisher_did = clavis_protocol::did_key_ed25519(&publisher.verifying_key().to_bytes());
    let message = snapshot_message(&operators, expires_unix);
    let signature = publisher.sign(&message).to_bytes();
    Snapshot {
        operators,
        expires_unix,
        publisher_did,
        signature,
    }
}

pub fn classify(
    snapshot: Option<&Snapshot>,
    operator_key: &str,
    now_unix: u64,
    publisher: &VerifyingKey,
) -> Category {
    let Some(snapshot) = snapshot else {
        return Category::Unchecked;
    };
    if now_unix >= snapshot.expires_unix {
        return Category::Unchecked;
    }
    let message = snapshot_message(&snapshot.operators, snapshot.expires_unix);
    let signature = Signature::from_bytes(&snapshot.signature);
    if publisher.verify(&message, &signature).is_err() {
        return Category::Unchecked;
    }
    for operator in &snapshot.operators {
        if operator.keys.iter().any(|key| key == operator_key) {
            return match operator.category.as_str() {
                "trusted" => Category::Trusted,
                "registered" => Category::Registered,
                _ => Category::Unchecked,
            };
        }
    }
    Category::Unregistered
}

fn snapshot_message(operators: &[Operator], expires_unix: u64) -> Vec<u8> {
    let mut message = b"clavis-snapshot-v1".to_vec();
    message.extend_from_slice(&expires_unix.to_be_bytes());
    for operator in operators {
        message.extend_from_slice(operator.name.as_bytes());
        message.push(0);
        message.extend_from_slice(operator.category.as_bytes());
        message.push(0);
        for kind in &operator.kinds {
            message.extend_from_slice(kind.as_bytes());
            message.push(0);
        }
        for key in &operator.keys {
            message.extend_from_slice(key.as_bytes());
            message.push(0);
        }
        message.push(0xff);
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::OsRng;

    #[test]
    fn missing_snapshot_is_unchecked() {
        let publisher = SigningKey::generate(&mut OsRng);
        let verifying = publisher.verifying_key();
        assert_eq!(
            classify(None, "did:key:clinic", 1_700_000_000, &verifying),
            Category::Unchecked
        );
        assert_eq!(Category::Unchecked.label(), UNCHECKED_LABEL);

        let clinic = "did:key:clinic";
        let snapshot = sign_snapshot(
            vec![Operator {
                name: "Клиника".into(),
                category: "trusted".into(),
                kinds: vec!["medical".into(), "personal".into()],
                keys: vec![clinic.into()],
            }],
            1_800_000_000,
            &publisher,
        );
        assert_eq!(
            classify(Some(&snapshot), clinic, 1_700_000_000, &verifying),
            Category::Trusted
        );
        assert_eq!(
            classify(Some(&snapshot), clinic, 1_800_000_000, &verifying),
            Category::Unchecked
        );
        assert_eq!(
            classify(Some(&snapshot), "did:key:other", 1_700_000_000, &verifying),
            Category::Unregistered
        );
    }
}