use clavis_protocol::{open, release, verify_holder, verify_inclusion, Claim, Request};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

fn contains(haystack: &[u8], needle: &str) -> bool {
    let needle = needle.as_bytes();
    haystack.windows(needle.len()).any(|window| window == needle)
}

#[test]
fn freshness_one_field_encrypted_to_verifier() {
    let requested = "allergy:peanut";
    let withheld = "history:psychiatric-withheld";
    let claims = vec![
        Claim {
            path: "Patient.allergy".into(),
            value: requested.into(),
        },
        Claim {
            path: "Patient.history".into(),
            value: withheld.into(),
        },
    ];
    let holder = SigningKey::generate(&mut OsRng);
    let verifier_identity = SigningKey::generate(&mut OsRng);
    let verifier = StaticSecret::random_from_rng(OsRng);
    let verifier_public = PublicKey::from(&verifier);
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let request = Request {
        id: "req-medical-1".into(),
        verifier_did: clavis_protocol::did_key_ed25519(
            &verifier_identity.verifying_key().to_bytes(),
        ),
        verifier_x25519: verifier_public.to_bytes(),
        fields: vec!["Patient.allergy".into()],
        nonce,
        purpose: "данное обращение".into(),
        retention: "хранить до даты".into(),
    };

    let sealed = release(&claims, &request, &holder).unwrap();
    let on_wire = serde_json::to_vec(&sealed).unwrap();
    assert!(!contains(&on_wire, requested));
    assert!(!contains(&on_wire, withheld));

    let opened = open(&sealed, &verifier).unwrap();
    assert_eq!(opened.nonce, nonce);
    assert_eq!(opened.request_id, request.id);
    assert_eq!(opened.disclosed.len(), 1);
    assert_eq!(opened.disclosed[0].path, "Patient.allergy");
    assert_eq!(opened.disclosed[0].value.as_deref(), Some(requested));
    let plaintext = serde_json::to_vec(&opened).unwrap();
    assert!(contains(&plaintext, requested));
    assert!(!contains(&plaintext, withheld));
    assert!(verify_inclusion(&opened.disclosed[0], &opened.root));
    verify_holder(&opened).unwrap();

    let other = StaticSecret::random_from_rng(OsRng);
    assert!(open(&sealed, &other).is_err());
}