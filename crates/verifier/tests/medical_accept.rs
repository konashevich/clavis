use clavis_protocol::{release_carrying, verify_inclusion, CarriedIssuer, Claim, Request};
use clavis_verifier::{accept, IssuerAnchor, OpenRequests};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use rand::RngCore;
use x25519_dalek::{PublicKey, StaticSecret};

const ALLERGY: &str = "арахис";
const WITHHELD: &str = "скрытый-психиатрический-диагноз";
const ALLERGY_PATH: &str = "AllergyIntolerance.code";
const WITHHELD_PATH: &str = "Condition.code";
const KIND: &str = "AllergyIntolerance";
const CLINIC: &str = "Городская поликлиника №7";
const EXPIRES_AT: i64 = 1_700_000_000;

fn contains(haystack: &[u8], needle: &str) -> bool {
    let needle = needle.as_bytes();
    haystack
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

fn accept_once(
    sealed: &clavis_protocol::SealedPresentation,
    verifier: &StaticSecret,
    anchor: &IssuerAnchor,
    nonce: &[u8; 32],
    now: i64,
) -> Result<clavis_verifier::Accepted, clavis_verifier::Error> {
    let mut open = OpenRequests::new();
    open.insert(*nonce, EXPIRES_AT);
    accept(sealed, verifier, anchor, nonce, now, &mut open)
}

fn carried(issued: &clavis_issuer::Issued, kind: &str) -> CarriedIssuer {
    CarriedIssuer {
        did: issued.issuer_did.clone(),
        signature: issued.signature.to_vec(),
        kind: kind.into(),
    }
}

#[test]
fn medical_accept() {
    let clinic_key = SigningKey::generate(&mut OsRng);
    let issued = clavis_issuer::issue(&claims(), &clinic_key).unwrap();
    assert_eq!(issued.document["type"][0], "VerifiableCredential");
    assert_eq!(issued.document["type"][1], "FHIRResource");
    assert_eq!(
        issued.document["credentialSubject"]["resourceType"],
        "Patient"
    );
    assert_eq!(issued.document["credentialSubject"][ALLERGY_PATH], ALLERGY);
    assert_eq!(
        issued.document["credentialSubject"][WITHHELD_PATH],
        WITHHELD
    );
    assert_eq!(issued.document["proof"]["origin"], "подписано эмитентом");

    let holder = SigningKey::generate(&mut OsRng);
    let verifier_identity = SigningKey::generate(&mut OsRng);
    let verifier = StaticSecret::random_from_rng(OsRng);
    let verifier_public = PublicKey::from(&verifier);
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);
    let request = Request {
        id: "req-clinic-allergy".into(),
        verifier_did: clavis_protocol::did_key_ed25519(
            &verifier_identity.verifying_key().to_bytes(),
        ),
        verifier_x25519: verifier_public.to_bytes(),
        fields: vec![ALLERGY_PATH.into()],
        nonce,
        purpose: "приём в поликлинике".into(),
        retention: "данное обращение".into(),
        form: clavis_protocol::RequestForm::Dynamic,
        expires_at: Some(EXPIRES_AT),
        kinds: vec!["medical".into()],
        portrait: false,
        document_number: false,
        signature: Vec::new(),
    };
    let anchor = IssuerAnchor {
        name: CLINIC.into(),
        issuer_did: issued.issuer_did.clone(),
        kinds: vec![KIND.into()],
    };
    let issuer = carried(&issued, KIND);
    let sealed = release_carrying(&claims(), &request, &holder, Some(&issuer), EXPIRES_AT).unwrap();

    let on_wire = serde_json::to_vec(&sealed).unwrap();
    assert!(!contains(&on_wire, ALLERGY));
    assert!(!contains(&on_wire, WITHHELD));
    assert!(!contains(&on_wire, CLINIC));
    assert!(!contains(&sealed.ciphertext, ALLERGY));
    assert!(!contains(&sealed.ciphertext, WITHHELD));
    assert!(!contains(&sealed.ciphertext, "подпись эмитента принята"));
    assert!(!contains(&sealed.ciphertext, "внесено человеком"));
    assert!(!contains(&sealed.ciphertext, "подписано эмитентом"));

    let accepted = accept_once(&sealed, &verifier, &anchor, &nonce, EXPIRES_AT + 120).unwrap();
    assert_eq!(accepted.presentation.nonce, nonce);
    assert_eq!(accepted.presentation.request_id, request.id);
    assert_eq!(accepted.presentation.root, issued.root);
    assert_eq!(accepted.presentation.disclosed.len(), 1);
    assert_eq!(accepted.presentation.disclosed[0].path, ALLERGY_PATH);
    assert_eq!(
        accepted.presentation.disclosed[0].value.as_deref(),
        Some(ALLERGY)
    );
    assert!(verify_inclusion(
        &accepted.presentation.disclosed[0],
        &accepted.presentation.root
    ));
    assert_eq!(accepted.origin, "подпись эмитента принята");
    assert_eq!(accepted.anchor_name.as_deref(), Some(CLINIC));
    assert_ne!(
        accepted.origin,
        issued.document["proof"]["origin"].as_str().unwrap()
    );

    let opened = serde_json::to_vec(&accepted.presentation).unwrap();
    assert!(contains(&opened, ALLERGY));
    assert!(!contains(&opened, WITHHELD));
    assert!(!contains(&opened, WITHHELD_PATH));
    assert!(!contains(&opened, CLINIC));
    assert!(!contains(&opened, "подпись эмитента принята"));
    assert!(!contains(&opened, "внесено человеком"));

    let mut renamed = anchor.clone();
    renamed.name = "Другая поликлиника".into();
    let renamed_accept =
        accept_once(&sealed, &verifier, &renamed, &nonce, EXPIRES_AT + 120).unwrap();
    assert_eq!(renamed_accept.origin, "подпись эмитента принята");
    assert_eq!(
        renamed_accept.anchor_name.as_deref(),
        Some("Другая поликлиника")
    );

    let other = StaticSecret::random_from_rng(OsRng);
    assert_eq!(
        accept_once(&sealed, &other, &anchor, &nonce, EXPIRES_AT + 120).unwrap_err(),
        clavis_verifier::Error::Open(clavis_protocol::Error::Decrypt)
    );

    let mut wrong_nonce = nonce;
    wrong_nonce[0] ^= 0xff;
    assert_eq!(
        accept_once(&sealed, &verifier, &anchor, &wrong_nonce, EXPIRES_AT + 120).unwrap_err(),
        clavis_verifier::Error::Freshness
    );
    assert_eq!(
        accept_once(&sealed, &verifier, &anchor, &nonce, EXPIRES_AT + 121).unwrap_err(),
        clavis_verifier::Error::Freshness
    );

    let foreign_key = SigningKey::generate(&mut OsRng);
    let foreign = clavis_issuer::issue(&claims(), &foreign_key).unwrap();
    assert_ne!(foreign.issuer_did, anchor.issuer_did);
    assert_eq!(foreign.root, issued.root);
    let foreign_issuer = carried(&foreign, KIND);
    let foreign_sealed = release_carrying(
        &claims(),
        &request,
        &holder,
        Some(&foreign_issuer),
        EXPIRES_AT,
    )
    .unwrap();
    let foreign_accepted = accept_once(
        &foreign_sealed,
        &verifier,
        &anchor,
        &nonce,
        EXPIRES_AT + 120,
    )
    .unwrap();
    assert_eq!(foreign_accepted.origin, "подпись без признанного эмитента");
    assert!(foreign_accepted.anchor_name.is_none());
    assert!(verify_inclusion(
        &foreign_accepted.presentation.disclosed[0],
        &foreign_accepted.presentation.root
    ));

    let other_kind = carried(&issued, "Observation");
    let kind_sealed =
        release_carrying(&claims(), &request, &holder, Some(&other_kind), EXPIRES_AT).unwrap();
    let kind_accepted =
        accept_once(&kind_sealed, &verifier, &anchor, &nonce, EXPIRES_AT + 120).unwrap();
    assert_eq!(kind_accepted.origin, "подпись без признанного эмитента");
    assert!(kind_accepted.anchor_name.is_none());

    let self_sealed = release_carrying(&claims(), &request, &holder, None, EXPIRES_AT).unwrap();
    let self_on_wire = serde_json::to_vec(&self_sealed).unwrap();
    assert!(!contains(&self_on_wire, WITHHELD));
    assert!(!contains(&self_sealed.ciphertext, WITHHELD));
    let self_accepted =
        accept_once(&self_sealed, &verifier, &anchor, &nonce, EXPIRES_AT + 120).unwrap();
    assert_eq!(self_accepted.origin, "внесено человеком");
    assert!(self_accepted.anchor_name.is_none());
    assert_eq!(self_accepted.presentation.nonce, nonce);
    assert!(self_accepted.presentation.issuer_signature.is_none());
    assert!(verify_inclusion(
        &self_accepted.presentation.disclosed[0],
        &self_accepted.presentation.root
    ));
    let self_opened = serde_json::to_vec(&self_accepted.presentation).unwrap();
    assert!(contains(&self_opened, ALLERGY));
    assert!(!contains(&self_opened, WITHHELD));
    assert!(!contains(&self_opened, "внесено человеком"));
    assert!(!contains(&self_opened, "подписано эмитентом"));
}
