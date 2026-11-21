use clavis_holder::{
    generate_data_key, open_body, open_journal, seal_store, ArrivedStatement, ExportRefused,
    Journal, Module, SealedBody, SealedStore, StatementError, StatementKind, Store, TestModule,
    UnwrapFailed,
};
use clavis_protocol::{did_key_ed25519, Request};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;

const PURPOSE: &str = "приём в поликлинике";
const RETENTION: &str = "хранить до даты";
const NEW_RETENTION: &str = "хранить до 2031-06-01";
const REASON: &str = "законный срок хранения медицинской записи";

/// A verifier database the journal API cannot see.
struct VerifierDatabase {
    row_deleted: bool,
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn request(id: &str, verifier: &SigningKey, purpose: &str, retention: &str) -> Request {
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let mut verifier_x25519 = [0u8; 32];
    OsRng.fill_bytes(&mut verifier_x25519);
    Request {
        id: id.into(),
        verifier_did: did_key_ed25519(&verifier.verifying_key().to_bytes()),
        verifier_x25519,
        fields: vec!["AllergyIntolerance.code".into()],
        nonce,
        purpose: purpose.into(),
        retention: retention.into(),
    }
}

fn stored(sealed: &SealedStore) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&sealed.index_key.nonce);
    out.extend_from_slice(&sealed.index_key.ciphertext);
    out.extend_from_slice(&sealed.journal_key.nonce);
    out.extend_from_slice(&sealed.journal_key.ciphertext);
    push_body(&mut out, &sealed.index);
    push_body(&mut out, &sealed.journal);
    out
}

fn push_body(out: &mut Vec<u8>, body: &SealedBody) {
    out.extend_from_slice(&body.nonce);
    out.extend_from_slice(&body.ciphertext);
}

#[test]
fn deletion_statement() {
    let clinic_key = SigningKey::generate(&mut OsRng);
    let other_key = SigningKey::generate(&mut OsRng);
    let kept_key = SigningKey::generate(&mut OsRng);
    let silent_key = SigningKey::generate(&mut OsRng);
    let stranger_key = SigningKey::generate(&mut OsRng);

    let clinic = request("req-clinic-allergy", &clinic_key, PURPOSE, RETENTION);
    let other = request(
        "req-other-visit",
        &other_key,
        "регистрация на площадке",
        "не хранить",
    );
    let kept = request(
        "req-kept-record",
        &kept_key,
        "медицинская карта",
        "данное обращение",
    );
    let silent = request(
        "req-silent",
        &silent_key,
        "лабораторный запрос",
        "хранить без срока",
    );

    let mut journal = Journal::new();
    journal.record_request(clinic.clone());
    journal.record_request(other.clone());
    journal.record_request(kept.clone());
    journal.record_request(silent.clone());

    for stored_request in [&clinic, &other, &kept, &silent] {
        let row = journal.row(&stored_request.id).unwrap();
        assert_eq!(row.request, *stored_request);
        assert_eq!(row.request.purpose, stored_request.purpose);
        assert_eq!(row.request.retention, stored_request.retention);
        assert!(row.is_open());
        assert!(!row.is_deletion());
    }

    let mut verifier_database = VerifierDatabase { row_deleted: true };
    let while_flag_says_deleted = journal.clone();
    assert!(verifier_database.row_deleted);
    assert!(!journal.row(&clinic.id).unwrap().is_deletion());
    assert!(!journal.row(&silent.id).unwrap().is_deletion());
    verifier_database.row_deleted = false;
    assert_eq!(journal, while_flag_says_deleted);
    assert!(!verifier_database.row_deleted);
    assert!(journal.row(&silent.id).unwrap().is_open());

    let deletion_for_other =
        ArrivedStatement::signed(&other.id, StatementKind::Deletion, &other_key);
    journal.record_statement(&deletion_for_other).unwrap();
    assert!(journal.row(&other.id).unwrap().is_deletion());
    assert!(journal.row(&clinic.id).unwrap().is_open());
    assert!(!journal.row(&clinic.id).unwrap().is_deletion());
    assert!(journal.row(&kept.id).unwrap().is_open());
    assert!(journal.row(&silent.id).unwrap().is_open());

    let missing = ArrivedStatement::signed("req-missing", StatementKind::Deletion, &clinic_key);
    assert_eq!(
        journal.record_statement(&missing),
        Err(StatementError::UnknownRequest)
    );
    assert!(journal.row(&clinic.id).unwrap().is_open());

    let unsigned = ArrivedStatement::unsigned(&clinic.id, StatementKind::Deletion);
    assert_eq!(
        journal.record_statement(&unsigned),
        Err(StatementError::Unsigned)
    );
    assert!(journal.row(&clinic.id).unwrap().is_open());
    assert!(!journal.row(&clinic.id).unwrap().is_deletion());

    let other_key_on_clinic =
        ArrivedStatement::signed(&clinic.id, StatementKind::Deletion, &stranger_key);
    assert_eq!(
        journal.record_statement(&other_key_on_clinic),
        Err(StatementError::BadSignature)
    );
    let mut renamed = ArrivedStatement::signed(&other.id, StatementKind::Deletion, &other_key);
    renamed.request_id = clinic.id.clone();
    assert_eq!(
        journal.record_statement(&renamed),
        Err(StatementError::BadSignature)
    );
    assert!(journal.row(&clinic.id).unwrap().is_open());
    assert_eq!(
        journal.row(&clinic.id).unwrap().request.retention,
        RETENTION
    );

    let deletion_for_clinic =
        ArrivedStatement::signed(&clinic.id, StatementKind::Deletion, &clinic_key);
    journal.record_statement(&deletion_for_clinic).unwrap();
    assert!(!verifier_database.row_deleted);
    assert!(journal.row(&clinic.id).unwrap().is_deletion());
    assert!(!journal.row(&clinic.id).unwrap().is_open());
    assert_eq!(journal.row(&clinic.id).unwrap().request.purpose, PURPOSE);
    assert_eq!(
        journal.row(&clinic.id).unwrap().request.retention,
        RETENTION
    );
    verifier_database.row_deleted = true;
    assert!(journal.row(&clinic.id).unwrap().is_deletion());
    assert!(!journal.row(&silent.id).unwrap().is_deletion());

    let unsigned_keep = ArrivedStatement::unsigned(
        &kept.id,
        StatementKind::ContinuedStorage {
            retention: NEW_RETENTION.into(),
            reason: REASON.into(),
        },
    );
    assert_eq!(
        journal.record_statement(&unsigned_keep),
        Err(StatementError::Unsigned)
    );
    let stranger_keep = ArrivedStatement::signed(
        &kept.id,
        StatementKind::ContinuedStorage {
            retention: NEW_RETENTION.into(),
            reason: REASON.into(),
        },
        &stranger_key,
    );
    assert_eq!(
        journal.record_statement(&stranger_keep),
        Err(StatementError::BadSignature)
    );
    let mut tampered_reason = ArrivedStatement::signed(
        &kept.id,
        StatementKind::ContinuedStorage {
            retention: NEW_RETENTION.into(),
            reason: REASON.into(),
        },
        &kept_key,
    );
    match &mut tampered_reason.kind {
        StatementKind::ContinuedStorage { reason, .. } => reason.push('!'),
        StatementKind::Deletion => panic!("continued storage"),
    }
    assert_eq!(
        journal.record_statement(&tampered_reason),
        Err(StatementError::BadSignature)
    );
    assert!(journal.row(&kept.id).unwrap().is_open());
    assert!(journal.row(&kept.id).unwrap().continued_storage().is_none());

    let continued = ArrivedStatement::signed(
        &kept.id,
        StatementKind::ContinuedStorage {
            retention: NEW_RETENTION.into(),
            reason: REASON.into(),
        },
        &kept_key,
    );
    journal.record_statement(&continued).unwrap();
    assert!(!journal.row(&kept.id).unwrap().is_deletion());
    assert_eq!(
        journal.row(&kept.id).unwrap().continued_storage(),
        Some((NEW_RETENTION, REASON))
    );
    assert_eq!(
        journal.row(&kept.id).unwrap().request.retention,
        "данное обращение"
    );
    assert_eq!(
        journal.row(&kept.id).unwrap().request.purpose,
        "медицинская карта"
    );
    assert!(journal.row(&silent.id).unwrap().is_open());
    assert!(!journal.row(&silent.id).unwrap().is_deletion());
    assert!(verifier_database.row_deleted);

    let plain = journal.to_bytes();
    for needle in [
        PURPOSE,
        RETENTION,
        NEW_RETENTION,
        REASON,
        clinic.id.as_str(),
        silent.id.as_str(),
        "лабораторный запрос",
    ] {
        assert!(contains(&plain, needle.as_bytes()));
    }

    let device = TestModule::generate();
    let other_device = TestModule::generate();
    assert_eq!(device.try_export(), Err(ExportRefused));
    let index_key = generate_data_key();
    let journal_key = generate_data_key();
    assert_ne!(index_key, journal_key);
    assert_ne!(device.public_bytes(), journal_key);

    let store = Store {
        index_key,
        journal_key,
        index: b"cards:allergy".to_vec(),
        journal: plain.clone(),
        containers: Vec::new(),
    };
    let sealed = seal_store(&device, &store);
    let sealed_bytes = stored(&sealed);
    for needle in [
        PURPOSE.as_bytes(),
        RETENTION.as_bytes(),
        NEW_RETENTION.as_bytes(),
        REASON.as_bytes(),
        clinic.id.as_bytes(),
        silent.id.as_bytes(),
        journal_key.as_slice(),
        index_key.as_slice(),
    ] {
        assert!(!contains(&sealed_bytes, needle));
    }
    assert_eq!(device.unwrap(&sealed.journal_key).unwrap(), journal_key);
    assert_eq!(other_device.unwrap(&sealed.journal_key), Err(UnwrapFailed));
    assert_eq!(device.try_export(), Err(ExportRefused));

    let opened = open_journal(&device, &sealed).unwrap();
    assert_eq!(opened, plain);
    assert_eq!(open_journal(&other_device, &sealed), Err(UnwrapFailed));
    assert_eq!(open_body(&index_key, &sealed.journal), Err(UnwrapFailed));
    assert_eq!(open_body(&journal_key, &sealed.index), Err(UnwrapFailed));

    let restored = Journal::from_bytes(&opened).unwrap();
    assert_eq!(restored, journal);
    assert!(restored.row(&clinic.id).unwrap().is_deletion());
    assert_eq!(
        restored.row(&kept.id).unwrap().continued_storage(),
        Some((NEW_RETENTION, REASON))
    );
    assert!(restored.row(&silent.id).unwrap().is_open());
    assert!(!restored.row(&silent.id).unwrap().is_deletion());
    assert!(verifier_database.row_deleted);
    assert_eq!(device.try_export(), Err(ExportRefused));
}
