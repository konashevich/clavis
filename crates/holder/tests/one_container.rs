use clavis_holder::{
    generate_data_key, open_body, open_index, open_journal, open_release, seal_store, Container,
    ContainerId, DataKeyWrap, ExportRefused, Module, OpenError, OpenedContainer, SealedBody,
    SealedContainer, SealedStore, Store, TestModule, UnwrapFailed,
};

const ALLERGY: ContainerId = ContainerId(*b"allergy-card-001");
const ACCOUNT: ContainerId = ContainerId(*b"account-card-002");

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

fn push_wrap(out: &mut Vec<u8>, wrap: &DataKeyWrap) {
    out.extend_from_slice(&wrap.nonce);
    out.extend_from_slice(&wrap.ciphertext);
}

fn push_body(out: &mut Vec<u8>, body: &SealedBody) {
    out.extend_from_slice(&body.nonce);
    out.extend_from_slice(&body.ciphertext);
}

fn stored(sealed: &SealedStore) -> Vec<u8> {
    let SealedStore {
        index_key,
        journal_key,
        index,
        journal,
        containers,
    } = sealed;
    let mut out = Vec::new();
    push_wrap(&mut out, index_key);
    push_wrap(&mut out, journal_key);
    push_body(&mut out, index);
    push_body(&mut out, journal);
    for container in containers {
        let SealedContainer { id, key, body } = container;
        out.extend_from_slice(&id.0);
        push_wrap(&mut out, key);
        push_body(&mut out, body);
    }
    out
}

fn yielded(opened: &OpenedContainer) -> Vec<u8> {
    let OpenedContainer { id, plaintext } = opened;
    let mut out = id.0.to_vec();
    out.extend_from_slice(plaintext);
    out
}

#[test]
fn one_release_opens_one_container() {
    let device = TestModule::generate();
    let other = TestModule::generate();
    assert_eq!(device.try_export(), Err(ExportRefused));
    assert_ne!(device.public_bytes(), other.public_bytes());

    let index_key = generate_data_key();
    let journal_key = generate_data_key();
    let allergy_key = generate_data_key();
    let account_key = generate_data_key();
    assert_ne!(index_key, journal_key);
    assert_ne!(index_key, allergy_key);
    assert_ne!(index_key, account_key);
    assert_ne!(journal_key, allergy_key);
    assert_ne!(journal_key, account_key);
    assert_ne!(allergy_key, account_key);

    let index = b"cards:allergy,account";
    let journal = b"releases:none";
    let allergy = b"FHIR AllergyIntolerance: peanut, confirmed";
    let account = b"ISO20022 account statement: balance hidden";

    let store = Store {
        index_key,
        journal_key,
        index: index.to_vec(),
        journal: journal.to_vec(),
        containers: vec![
            Container {
                id: ALLERGY,
                key: allergy_key,
                plaintext: allergy.to_vec(),
            },
            Container {
                id: ACCOUNT,
                key: account_key,
                plaintext: account.to_vec(),
            },
        ],
    };
    let sealed = seal_store(&device, &store);

    let stored_bytes = stored(&sealed);
    for secret in [
        index.as_slice(),
        journal.as_slice(),
        allergy.as_slice(),
        account.as_slice(),
        index_key.as_slice(),
        journal_key.as_slice(),
        allergy_key.as_slice(),
        account_key.as_slice(),
    ] {
        assert!(!contains(&stored_bytes, secret));
    }

    assert_eq!(device.unwrap(&sealed.index_key).unwrap(), index_key);
    assert_eq!(device.unwrap(&sealed.journal_key).unwrap(), journal_key);
    let sealed_allergy = sealed
        .containers
        .iter()
        .find(|container| container.id == ALLERGY)
        .unwrap();
    let sealed_account = sealed
        .containers
        .iter()
        .find(|container| container.id == ACCOUNT)
        .unwrap();
    assert_eq!(device.unwrap(&sealed_allergy.key).unwrap(), allergy_key);
    assert_eq!(device.unwrap(&sealed_account.key).unwrap(), account_key);
    assert_eq!(other.unwrap(&sealed_allergy.key), Err(UnwrapFailed));
    assert_eq!(other.unwrap(&sealed.index_key), Err(UnwrapFailed));
    assert_eq!(device.try_export(), Err(ExportRefused));

    assert_eq!(open_index(&device, &sealed).unwrap(), index);
    assert_eq!(open_journal(&device, &sealed).unwrap(), journal);
    assert_eq!(
        open_body(&allergy_key, &sealed_account.body),
        Err(UnwrapFailed)
    );
    assert_eq!(
        open_body(&account_key, &sealed_allergy.body),
        Err(UnwrapFailed)
    );
    assert_eq!(
        open_body(&index_key, &sealed_allergy.body),
        Err(UnwrapFailed)
    );
    assert_eq!(
        open_body(&journal_key, &sealed_allergy.body),
        Err(UnwrapFailed)
    );
    assert_eq!(open_body(&allergy_key, &sealed.index), Err(UnwrapFailed));
    assert_eq!(open_body(&allergy_key, &sealed.journal), Err(UnwrapFailed));

    let opened = open_release(&device, &sealed, ALLERGY).unwrap();
    assert_eq!(opened.id, ALLERGY);
    assert_eq!(opened.plaintext, allergy);
    let yielded_bytes = yielded(&opened);
    assert!(contains(&yielded_bytes, allergy));
    assert!(!contains(&yielded_bytes, account));
    assert!(!contains(&yielded_bytes, &allergy_key));
    assert!(!contains(&yielded_bytes, &account_key));
    assert!(!contains(&yielded_bytes, &index_key));
    assert!(!contains(&yielded_bytes, &journal_key));

    let opened_account = open_release(&device, &sealed, ACCOUNT).unwrap();
    assert_eq!(opened_account.plaintext, account);
    assert!(!contains(&yielded(&opened_account), allergy));
    assert!(!contains(&yielded(&opened_account), &allergy_key));

    assert_eq!(
        open_release(&other, &sealed, ALLERGY),
        Err(OpenError::Sealed(UnwrapFailed))
    );
    assert_eq!(
        open_release(&device, &sealed, ContainerId(*b"missing-card-000")),
        Err(OpenError::UnknownContainer)
    );
}
