use clavis_registry::{
    classify, serialize_published_snapshot, serialize_snapshot_fetch_request, sign_snapshot,
    snapshot_fetch_request, Category, Operator, SnapshotPublisher, SNAPSHOT_FETCH_REQUEST_BYTES,
};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;

fn contains(haystack: &[u8], needle: &str) -> bool {
    let needle = needle.as_bytes();
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[test]
fn full_snapshot_fetch_omits_encountered_key() {
    let publisher_key = SigningKey::generate(&mut OsRng);
    let clinic_signing = SigningKey::generate(&mut OsRng);
    let bank_signing = SigningKey::generate(&mut OsRng);
    let encountered = clavis_protocol::did_key_ed25519(&clinic_signing.verifying_key().to_bytes());
    let bank_did = clavis_protocol::did_key_ed25519(&bank_signing.verifying_key().to_bytes());
    assert!(encountered.starts_with("did:key:"));
    assert_ne!(encountered, bank_did);

    let request = snapshot_fetch_request();
    let request_bytes = serialize_snapshot_fetch_request(&request);
    assert_eq!(request_bytes, SNAPSHOT_FETCH_REQUEST_BYTES);
    assert!(!contains(&request_bytes, &encountered));

    let expires_unix = 1_800_000_000_u64;
    let clinic = Operator {
        name: "Клиника".into(),
        category: "trusted".into(),
        kinds: vec!["medical".into()],
        keys: vec![encountered.clone()],
    };
    let bank = Operator {
        name: "Банк".into(),
        category: "registered".into(),
        kinds: vec!["financial".into()],
        keys: vec![bank_did.clone()],
    };
    let first = sign_snapshot(
        vec![clinic.clone(), bank.clone()],
        expires_unix,
        &publisher_key,
    );
    let mut publisher = SnapshotPublisher::new();
    let published = publisher.publish(first.clone());
    assert_eq!(
        publisher.answer(&request).as_deref(),
        Some(published.as_slice())
    );
    assert_eq!(published, serialize_published_snapshot(&first));
    assert_eq!(publisher.current(), Some(&first));

    assert!(contains(&published, &encountered));
    assert!(contains(&published, &bank_did));
    assert!(contains(&published, &clinic.name));
    assert!(contains(&published, &bank.name));
    assert!(contains(&published, &clinic.category));
    assert!(contains(&published, &bank.category));
    assert!(contains(&published, &clinic.kinds[0]));
    assert!(contains(&published, &bank.kinds[0]));
    assert!(contains(&published, &first.publisher_did));
    assert!(contains_bytes(&published, &expires_unix.to_be_bytes()));
    assert!(contains_bytes(&published, &first.signature));

    let verifying = publisher_key.verifying_key();
    let now = 1_700_000_000;
    assert_eq!(
        classify(Some(&first), &encountered, now, &verifying),
        Category::Trusted
    );
    assert_eq!(
        classify(Some(&first), &bank_did, now, &verifying),
        Category::Registered
    );

    let second = sign_snapshot(vec![bank], expires_unix, &publisher_key);
    let replaced = publisher.publish(second.clone());
    assert_eq!(
        publisher.answer(&request).as_deref(),
        Some(replaced.as_slice())
    );
    assert_eq!(publisher.current(), Some(&second));
    assert!(!contains(&replaced, &encountered));
    assert!(contains(&replaced, &bank_did));
    assert_eq!(
        classify(publisher.current(), &encountered, now, &verifying),
        Category::Unregistered
    );
    assert_eq!(
        classify(publisher.current(), &bank_did, now, &verifying),
        Category::Registered
    );
}
