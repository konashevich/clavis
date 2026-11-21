use clavis_holder::{
    rewrap_with_passphrase, unwrap_data_keys, unwrap_with_passphrase, wrap_data_keys,
    wrap_with_passphrase, DataKeyWraps, DataKeys, ExportRefused, Module, TestModule, UnwrapFailed,
};

fn stored(wraps: &DataKeyWraps) -> Vec<u8> {
    let mut out = Vec::new();
    for wrap in [&wraps.index, &wraps.journal, &wraps.container] {
        out.extend_from_slice(&wrap.nonce);
        out.extend_from_slice(&wrap.ciphertext);
    }
    out
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

#[test]
fn passphrase_rewraps_data_keys_onto_a_new_device() {
    let old_device = TestModule::generate();
    let new_device = TestModule::generate();
    assert_ne!(old_device.public_bytes(), new_device.public_bytes());

    let keys = DataKeys::generate();
    assert_ne!(keys.index, keys.journal);
    assert_ne!(keys.index, keys.container);
    assert_ne!(keys.journal, keys.container);

    let passphrase = b"spare-secret-after-a-new-fingerprint";
    let device_wraps = wrap_data_keys(&old_device, &keys);
    let recovery = wrap_with_passphrase(passphrase, &keys);

    let mut stored_bytes = stored(&recovery);
    stored_bytes.extend(stored(&device_wraps));
    assert!(!contains(&stored_bytes, passphrase));
    assert!(!contains(&stored_bytes, &keys.index));
    assert!(!contains(&stored_bytes, &keys.journal));
    assert!(!contains(&stored_bytes, &keys.container));

    assert_eq!(
        unwrap_with_passphrase(b"wrong-passphrase", &recovery),
        Err(UnwrapFailed)
    );
    assert_eq!(
        rewrap_with_passphrase(&new_device, b"wrong-passphrase", &recovery),
        Err(UnwrapFailed)
    );
    assert_eq!(unwrap_with_passphrase(passphrase, &recovery).unwrap(), keys);

    let rewrapped = rewrap_with_passphrase(&new_device, passphrase, &recovery).unwrap();
    assert!(!contains(&stored(&rewrapped), passphrase));
    assert_eq!(unwrap_data_keys(&new_device, &rewrapped).unwrap(), keys);

    assert_eq!(old_device.unwrap(&rewrapped.index), Err(UnwrapFailed));
    assert_eq!(old_device.unwrap(&rewrapped.journal), Err(UnwrapFailed));
    assert_eq!(old_device.unwrap(&rewrapped.container), Err(UnwrapFailed));
    assert_eq!(new_device.unwrap(&device_wraps.index), Err(UnwrapFailed));
    assert_eq!(new_device.unwrap(&device_wraps.journal), Err(UnwrapFailed));
    assert_eq!(
        new_device.unwrap(&device_wraps.container),
        Err(UnwrapFailed)
    );

    assert_eq!(old_device.try_export(), Err(ExportRefused));
    assert_eq!(new_device.try_export(), Err(ExportRefused));
}
