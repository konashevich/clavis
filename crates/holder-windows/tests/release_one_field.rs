use clavis_holder_windows::Holder;
use clavis_protocol::{open, Claim, Request};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

const ALLERGY: &str = "арахис";
const WITHHELD: &str = "скрытый-психиатрический-диагноз";
const ALLERGY_PATH: &str = "AllergyIntolerance.code";
const WITHHELD_PATH: &str = "Condition.code";

fn contains(haystack: &[u8], needle: &str) -> bool {
    let needle = needle.as_bytes();
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn claims() -> Vec<Claim> {
    vec![
        Claim {
            path: ALLERGY_PATH.into(),
            value: ALLERGY.into(),
        },
        Claim {
            path: WITHHELD_PATH.into(),
            value: WITHHELD.into(),
        },
    ]
}

fn request(verifier_did: &str, verifier_x25519: [u8; 32], nonce: [u8; 32]) -> Request {
    Request {
        id: "req-clinic-allergy".into(),
        verifier_did: verifier_did.into(),
        verifier_x25519,
        fields: vec![ALLERGY_PATH.into()],
        nonce,
        purpose: "приём в поликлинике".into(),
        retention: "данное обращение".into(),
    }
}

#[test]
fn release_one_field() {
    assert!(clavis_holder_windows::boot(false).is_err());

    let verifier_identity = SigningKey::generate(&mut OsRng);
    let verifier_did =
        clavis_protocol::did_key_ed25519(&verifier_identity.verifying_key().to_bytes());
    let verifier = StaticSecret::random_from_rng(OsRng);
    let verifier_public = PublicKey::from(&verifier);
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);

    let holder = Holder::start(claims()).unwrap();
    let request = request(&verifier_did, verifier_public.to_bytes(), nonce);
    let sealed = holder.release(&request).unwrap();

    let wire = serde_json::to_vec(&sealed).unwrap();
    assert!(!contains(&wire, ALLERGY));
    assert!(!contains(&wire, WITHHELD));
    assert!(!contains(&sealed.ciphertext, ALLERGY));
    assert!(!contains(&sealed.ciphertext, WITHHELD));

    let opened = open(&sealed, &verifier).unwrap();
    assert_eq!(opened.nonce, nonce);
    assert_eq!(opened.request_id, request.id);
    assert_eq!(opened.disclosed.len(), 1);
    assert_eq!(opened.disclosed[0].path, ALLERGY_PATH);
    assert_eq!(opened.disclosed[0].value.as_deref(), Some(ALLERGY));
    assert!(opened
        .disclosed
        .iter()
        .all(|item| item.path != WITHHELD_PATH));
    let plaintext = serde_json::to_vec(&opened).unwrap();
    assert!(contains(&plaintext, ALLERGY));
    assert!(!contains(&plaintext, WITHHELD));
    assert_eq!(opened.holder_did, holder.pairwise_did());
    assert_ne!(opened.holder_did, holder.device_did());
    assert!(holder.keys_remain_inside());
}
