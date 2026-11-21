//! Consent modes and one-nonce replay.
//!
//! Licensed: trusted key, every kind in that operator's list, dynamic, one confirmation.
//! Ordinary: registered, kinds match, no medical or financial kind, no portrait, no document number.
//! Heightened: the remaining requests, dynamic, two confirmations.

use clavis_holder::{
    Card, Consent, ConsentMode, JournalEvent, PairwiseKey, Refusal, ReleaseError,
    CLOCK_SKEW_SECONDS, KIND_EDUCATION, KIND_FINANCIAL, KIND_MEDICAL, KIND_PERSONAL,
};
use clavis_protocol::{sign_request, Claim, Request, RequestForm};
use clavis_registry::{sign_snapshot, Category, Operator, Snapshot, UNCHECKED_LABEL};
use clavis_verifier::{accept, IssuerAnchor, OpenRequests};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

const NOW: i64 = 1_700_000_000;
const LIVE_UNTIL: u64 = 1_900_000_000;
const ALLERGY: &str = "арахис";
const WITHHELD: &str = "скрытый-психиатрический-диагноз";
const NAME_PATH: &str = "Patient.name";
const ALLERGY_PATH: &str = "AllergyIntolerance.code";
const WITHHELD_PATH: &str = "Condition.code";
const PURPOSE: &str = "приём в поликлинике";

struct Party {
    signing: SigningKey,
    did: String,
    secret: StaticSecret,
    x25519: [u8; 32],
}

fn party() -> Party {
    let signing = SigningKey::generate(&mut OsRng);
    let did = clavis_protocol::did_key_ed25519(&signing.verifying_key().to_bytes());
    let secret = StaticSecret::random_from_rng(OsRng);
    let x25519 = PublicKey::from(&secret).to_bytes();
    Party {
        signing,
        did,
        secret,
        x25519,
    }
}

fn operator(name: &str, category: &str, kinds: &[&str], party: &Party) -> Operator {
    Operator {
        name: name.into(),
        category: category.into(),
        kinds: kinds.iter().map(|kind| (*kind).to_string()).collect(),
        keys: vec![party.did.clone()],
    }
}

fn directory(publisher: &SigningKey, operators: Vec<Operator>) -> Snapshot {
    sign_snapshot(operators, LIVE_UNTIL, publisher)
}

fn claims() -> Vec<Claim> {
    vec![
        Claim {
            path: NAME_PATH.into(),
            value: "Анна".into(),
        },
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

struct Ask<'a> {
    id: &'a str,
    fields: Vec<String>,
    kinds: Vec<String>,
    form: RequestForm,
    expires_at: Option<i64>,
    portrait: bool,
    document_number: bool,
    cover_recipient: bool,
}

fn ask(party: &Party, ask: Ask<'_>) -> Request {
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let mut request = Request {
        id: ask.id.into(),
        verifier_did: party.did.clone(),
        verifier_x25519: party.x25519,
        fields: ask.fields,
        nonce,
        purpose: PURPOSE.into(),
        retention: "данное обращение".into(),
        form: ask.form,
        expires_at: ask.expires_at,
        kinds: ask.kinds,
        portrait: ask.portrait,
        document_number: ask.document_number,
        signature: Vec::new(),
    };
    sign_request(&mut request, &party.signing, ask.cover_recipient);
    request
}

fn dynamic(party: &Party, id: &str, kinds: &[&str]) -> Request {
    ask(
        party,
        Ask {
            id,
            fields: vec![NAME_PATH.into()],
            kinds: kinds.iter().map(|kind| (*kind).to_string()).collect(),
            form: RequestForm::Dynamic,
            expires_at: Some(NOW + 600),
            portrait: false,
            document_number: false,
            cover_recipient: true,
        },
    )
}

fn contains(haystack: &[u8], needle: &str) -> bool {
    let needle = needle.as_bytes();
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn last_refusal<'a>(consent: &'a Consent, id: &str, reason: Refusal) {
    match consent.journal().last() {
        Some(JournalEvent::Refusal {
            request_id,
            reason: got,
        }) => {
            assert_eq!(request_id, id);
            assert_eq!(*got, reason);
        }
        other => panic!("expected a recorded refusal, got {other:?}"),
    }
}

fn review<'a>(
    consent: &'a mut Consent,
    request: &Request,
    snapshot: Option<&Snapshot>,
    publisher: &SigningKey,
) -> Result<Card, Refusal> {
    consent.review(request, snapshot, NOW, &publisher.verifying_key())
}

#[test]
fn trusted_dynamic_one_confirmation_then_replay() {
    assert_eq!(CLOCK_SKEW_SECONDS, clavis_verifier::CLOCK_SKEW_SECONDS);

    let publisher = SigningKey::generate(&mut OsRng);
    let clinic = party();
    let snapshot = directory(
        &publisher,
        vec![operator(
            "Городская поликлиника",
            "trusted",
            &[KIND_MEDICAL, KIND_PERSONAL],
            &clinic,
        )],
    );
    let request = ask(
        &clinic,
        Ask {
            id: "req-clinic",
            fields: vec![NAME_PATH.into(), ALLERGY_PATH.into()],
            kinds: vec![KIND_MEDICAL.into(), KIND_PERSONAL.into()],
            form: RequestForm::Dynamic,
            expires_at: Some(NOW + 600),
            portrait: true,
            document_number: true,
            cover_recipient: true,
        },
    );
    let mut consent = Consent::new();
    let key = PairwiseKey::generate();
    let card = review(&mut consent, &request, Some(&snapshot), &publisher).unwrap();
    assert_eq!(card.mode(), ConsentMode::Licensed);
    assert_eq!(card.category(), Category::Trusted);
    assert_eq!(card.category().label(), "доверенный");
    assert_eq!(card.operator_name(), "Городская поликлиника");
    assert_eq!(card.confirmations_required(), 1);
    assert_eq!(card.request().purpose, PURPOSE);
    assert!(consent.journal().is_empty());

    let stored = claims();
    assert_eq!(
        consent.release(&card, 0, &stored, &key).unwrap_err(),
        ReleaseError::NeedConfirmation { got: 0, need: 1 }
    );
    assert!(consent.journal().is_empty());

    let sealed = consent.release(&card, 1, &stored, &key).unwrap();
    assert!(!contains(&sealed.ciphertext, ALLERGY));
    assert!(!contains(&sealed.ciphertext, WITHHELD));
    assert_eq!(
        consent.release(&card, 1, &stored, &key).unwrap_err(),
        ReleaseError::NonceReused
    );
    assert_eq!(
        consent
            .journal()
            .iter()
            .filter(|event| matches!(event, JournalEvent::Release { .. }))
            .count(),
        1
    );

    let anchor = IssuerAnchor {
        name: "Городская поликлиника".into(),
        issuer_did: "did:key:zunused".into(),
        kinds: vec![KIND_MEDICAL.into()],
    };
    let nonce = card.request().nonce;
    let mut closed = OpenRequests::new();
    assert_eq!(
        accept(&sealed, &clinic.secret, &anchor, &nonce, NOW, &mut closed).unwrap_err(),
        clavis_verifier::Error::Freshness
    );
    let mut open = OpenRequests::new();
    open.insert(nonce, NOW + 600);
    let accepted = accept(&sealed, &clinic.secret, &anchor, &nonce, NOW, &mut open).unwrap();
    assert_eq!(accepted.presentation.nonce, nonce);
    assert_eq!(accepted.presentation.request_id, "req-clinic");
    assert_eq!(accepted.presentation.disclosed.len(), 2);
    assert!(accepted
        .presentation
        .disclosed
        .iter()
        .any(|item| item.value.as_deref() == Some(ALLERGY)));
    assert!(accepted
        .presentation
        .disclosed
        .iter()
        .all(|item| item.path != WITHHELD_PATH && item.value.as_deref() != Some(WITHHELD)));
    assert_eq!(
        accept(&sealed, &clinic.secret, &anchor, &nonce, NOW, &mut open).unwrap_err(),
        clavis_verifier::Error::Replay
    );
    open.insert(nonce, NOW + 600);
    assert_eq!(
        accept(&sealed, &clinic.secret, &anchor, &nonce, NOW, &mut open).unwrap_err(),
        clavis_verifier::Error::Replay
    );

    let again = ask(
        &clinic,
        Ask {
            id: "req-clinic-next",
            fields: vec![ALLERGY_PATH.into()],
            kinds: vec![KIND_MEDICAL.into()],
            form: RequestForm::Dynamic,
            expires_at: Some(NOW + 600),
            portrait: false,
            document_number: false,
            cover_recipient: true,
        },
    );
    let next = review(&mut consent, &again, Some(&snapshot), &publisher).unwrap();
    assert_eq!(next.mode(), ConsentMode::Licensed);
    let second = consent.release(&next, 1, &stored, &key).unwrap();
    assert_ne!(second.ciphertext, sealed.ciphertext);
    assert_eq!(
        consent.release(&next, 1, &stored, &key).unwrap_err(),
        ReleaseError::NonceReused
    );
}

#[test]
fn ordinary_allows_static_or_dynamic_with_one_confirmation() {
    let publisher = SigningKey::generate(&mut OsRng);
    let school = party();
    let shop = party();
    let snapshot = directory(
        &publisher,
        vec![
            operator("Университет", "registered", &[KIND_EDUCATION], &school),
            operator("Магазин", "registered", &[KIND_PERSONAL], &shop),
        ],
    );
    let mut consent = Consent::new();
    let key = PairwiseKey::generate();
    let stored = claims();

    let static_ask = ask(
        &school,
        Ask {
            id: "req-school",
            fields: vec!["alumniOf".into()],
            kinds: vec![KIND_EDUCATION.into()],
            form: RequestForm::Static,
            expires_at: Some(NOW + 86_400),
            portrait: false,
            document_number: false,
            cover_recipient: true,
        },
    );
    let card = review(&mut consent, &static_ask, Some(&snapshot), &publisher).unwrap();
    assert_eq!(card.mode(), ConsentMode::Ordinary);
    assert_eq!(card.category(), Category::Registered);
    assert_eq!(card.category().label(), "зарегистрированный");
    assert_eq!(card.operator_name(), "Университет");
    assert_eq!(card.confirmations_required(), 1);
    let sealed = consent.release(&card, 1, &stored, &key).unwrap();
    assert!(!sealed.ciphertext.is_empty());

    let dynamic_ask = dynamic(&shop, "req-shop", &[KIND_PERSONAL]);
    let card = review(&mut consent, &dynamic_ask, Some(&snapshot), &publisher).unwrap();
    assert_eq!(card.mode(), ConsentMode::Ordinary);
    assert_eq!(card.operator_name(), "Магазин");
    consent.release(&card, 1, &stored, &key).unwrap();
    assert_eq!(
        consent.release(&card, 1, &stored, &key).unwrap_err(),
        ReleaseError::NonceReused
    );
}

#[test]
fn heightened_needs_two_confirmations() {
    let publisher = SigningKey::generate(&mut OsRng);
    let stranger = party();
    let clinic = party();
    let shop = party();
    let cashier = party();
    let desk = party();
    let snapshot = directory(
        &publisher,
        vec![
            operator("Городская поликлиника", "trusted", &[KIND_MEDICAL], &clinic),
            operator("Магазин", "registered", &[KIND_PERSONAL], &shop),
            operator("Касса", "registered", &[KIND_FINANCIAL], &cashier),
            operator("Регистратура", "registered", &[KIND_MEDICAL], &desk),
        ],
    );
    let mut consent = Consent::new();
    let key = PairwiseKey::generate();
    let stored = claims();

    let cases = [
        dynamic(&stranger, "req-stranger", &[KIND_PERSONAL]),
        dynamic(&clinic, "req-foreign-kind", &[KIND_FINANCIAL]),
        dynamic(&shop, "req-shop-medical", &[KIND_MEDICAL]),
        dynamic(&cashier, "req-cashier", &[KIND_FINANCIAL]),
        dynamic(&desk, "req-registered-medical", &[KIND_MEDICAL]),
        ask(
            &shop,
            Ask {
                id: "req-portrait",
                fields: vec![NAME_PATH.into()],
                kinds: vec![KIND_PERSONAL.into()],
                form: RequestForm::Dynamic,
                expires_at: Some(NOW + 600),
                portrait: true,
                document_number: false,
                cover_recipient: true,
            },
        ),
        ask(
            &shop,
            Ask {
                id: "req-document-number",
                fields: vec![NAME_PATH.into()],
                kinds: vec![KIND_PERSONAL.into()],
                form: RequestForm::Dynamic,
                expires_at: Some(NOW + 600),
                portrait: false,
                document_number: true,
                cover_recipient: true,
            },
        ),
    ];

    for request in cases {
        let card = review(&mut consent, &request, Some(&snapshot), &publisher).unwrap();
        assert_eq!(card.mode(), ConsentMode::Heightened, "{}", request.id);
        assert_eq!(card.confirmations_required(), 2, "{}", request.id);
        assert_eq!(
            consent.release(&card, 1, &stored, &key).unwrap_err(),
            ReleaseError::NeedConfirmation { got: 1, need: 2 },
            "{}",
            request.id
        );
        consent.release(&card, 2, &stored, &key).unwrap();
        assert_eq!(
            consent.release(&card, 2, &stored, &key).unwrap_err(),
            ReleaseError::NonceReused,
            "{}",
            request.id
        );
    }

    let unchecked = dynamic(&clinic, "req-no-snapshot", &[KIND_MEDICAL]);
    let card = review(&mut consent, &unchecked, None, &publisher).unwrap();
    assert_eq!(card.mode(), ConsentMode::Heightened);
    assert_eq!(card.category(), Category::Unchecked);
    assert_eq!(card.category().label(), UNCHECKED_LABEL);
    assert_eq!(card.operator_name(), UNCHECKED_LABEL);
    assert_eq!(
        consent.release(&card, 1, &stored, &key).unwrap_err(),
        ReleaseError::NeedConfirmation { got: 1, need: 2 }
    );

    let mut expired = directory(
        &publisher,
        vec![operator(
            "Городская поликлиника",
            "trusted",
            &[KIND_MEDICAL],
            &clinic,
        )],
    );
    expired.expires_unix = NOW as u64;
    let request = dynamic(&clinic, "req-expired-snapshot", &[KIND_MEDICAL]);
    let card = review(&mut consent, &request, Some(&expired), &publisher).unwrap();
    assert_eq!(card.category(), Category::Unchecked);
    assert_eq!(card.mode(), ConsentMode::Heightened);

    let other = SigningKey::generate(&mut OsRng);
    let forged = directory(
        &other,
        vec![operator(
            "Поддельная клиника",
            "trusted",
            &[KIND_MEDICAL],
            &clinic,
        )],
    );
    let request = dynamic(&clinic, "req-forged-snapshot", &[KIND_MEDICAL]);
    let card = review(&mut consent, &request, Some(&forged), &publisher).unwrap();
    assert_eq!(card.category(), Category::Unchecked);
    assert_eq!(card.mode(), ConsentMode::Heightened);
    assert_eq!(card.operator_name(), UNCHECKED_LABEL);
    assert_ne!(card.operator_name(), "Поддельная клиника");
}

#[test]
fn refuses_before_a_card() {
    let publisher = SigningKey::generate(&mut OsRng);
    let clinic = party();
    let stranger = party();
    let snapshot = directory(
        &publisher,
        vec![operator(
            "Городская поликлиника",
            "trusted",
            &[KIND_MEDICAL, KIND_PERSONAL],
            &clinic,
        )],
    );
    let mut consent = Consent::new();

    let mut broken = dynamic(&clinic, "req-broken", &[KIND_MEDICAL]);
    broken.signature[0] ^= 0xff;
    assert_eq!(
        review(&mut consent, &broken, Some(&snapshot), &publisher).unwrap_err(),
        Refusal::BrokenSignature
    );
    last_refusal(&consent, "req-broken", Refusal::BrokenSignature);

    let mut swapped = dynamic(&clinic, "req-swapped-key", &[KIND_MEDICAL]);
    swapped.verifier_x25519[0] ^= 0xff;
    assert_eq!(
        review(&mut consent, &swapped, Some(&snapshot), &publisher).unwrap_err(),
        Refusal::BrokenSignature
    );
    last_refusal(&consent, "req-swapped-key", Refusal::BrokenSignature);

    let uncovered = ask(
        &clinic,
        Ask {
            id: "req-uncovered",
            fields: vec![ALLERGY_PATH.into()],
            kinds: vec![KIND_MEDICAL.into()],
            form: RequestForm::Dynamic,
            expires_at: Some(NOW + 600),
            portrait: false,
            document_number: false,
            cover_recipient: false,
        },
    );
    assert_eq!(
        review(&mut consent, &uncovered, Some(&snapshot), &publisher).unwrap_err(),
        Refusal::RecipientNotCovered
    );
    last_refusal(&consent, "req-uncovered", Refusal::RecipientNotCovered);

    let mut missing_expiry = dynamic(&clinic, "req-no-expiry", &[KIND_MEDICAL]);
    missing_expiry.expires_at = None;
    sign_request(&mut missing_expiry, &clinic.signing, true);
    assert_eq!(
        review(&mut consent, &missing_expiry, Some(&snapshot), &publisher).unwrap_err(),
        Refusal::Expired
    );
    last_refusal(&consent, "req-no-expiry", Refusal::Expired);

    let stale = ask(
        &clinic,
        Ask {
            id: "req-stale",
            fields: vec![ALLERGY_PATH.into()],
            kinds: vec![KIND_MEDICAL.into()],
            form: RequestForm::Dynamic,
            expires_at: Some(NOW - CLOCK_SKEW_SECONDS - 1),
            portrait: false,
            document_number: false,
            cover_recipient: true,
        },
    );
    assert_eq!(
        review(&mut consent, &stale, Some(&snapshot), &publisher).unwrap_err(),
        Refusal::Expired
    );
    last_refusal(&consent, "req-stale", Refusal::Expired);

    let edge = ask(
        &clinic,
        Ask {
            id: "req-skew-edge",
            fields: vec![ALLERGY_PATH.into()],
            kinds: vec![KIND_MEDICAL.into()],
            form: RequestForm::Dynamic,
            expires_at: Some(NOW - CLOCK_SKEW_SECONDS),
            portrait: false,
            document_number: false,
            cover_recipient: true,
        },
    );
    let card = review(&mut consent, &edge, Some(&snapshot), &publisher).unwrap();
    assert_eq!(card.mode(), ConsentMode::Licensed);

    let static_licensed = ask(
        &clinic,
        Ask {
            id: "req-static-licensed",
            fields: vec![ALLERGY_PATH.into()],
            kinds: vec![KIND_MEDICAL.into()],
            form: RequestForm::Static,
            expires_at: Some(NOW + 600),
            portrait: false,
            document_number: false,
            cover_recipient: true,
        },
    );
    assert_eq!(
        review(&mut consent, &static_licensed, Some(&snapshot), &publisher).unwrap_err(),
        Refusal::StaticRequiresDynamic
    );
    last_refusal(
        &consent,
        "req-static-licensed",
        Refusal::StaticRequiresDynamic,
    );

    let static_stranger = ask(
        &stranger,
        Ask {
            id: "req-static-stranger",
            fields: vec![NAME_PATH.into()],
            kinds: vec![KIND_PERSONAL.into()],
            form: RequestForm::Static,
            expires_at: Some(NOW + 600),
            portrait: false,
            document_number: false,
            cover_recipient: true,
        },
    );
    assert_eq!(
        review(&mut consent, &static_stranger, Some(&snapshot), &publisher).unwrap_err(),
        Refusal::StaticRequiresDynamic
    );
    last_refusal(
        &consent,
        "req-static-stranger",
        Refusal::StaticRequiresDynamic,
    );

    let mut static_broken = static_licensed;
    static_broken.id = "req-static-broken".into();
    assert_eq!(
        review(&mut consent, &static_broken, Some(&snapshot), &publisher).unwrap_err(),
        Refusal::BrokenSignature
    );
    last_refusal(&consent, "req-static-broken", Refusal::BrokenSignature);
}
