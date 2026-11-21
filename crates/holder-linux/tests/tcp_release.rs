use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::thread;
use std::time::Duration;

use clavis_holder_linux::{read_frame, write_frame, Frame, Holder, RejectReason};
use clavis_protocol::{verify_holder, verify_inclusion, Claim, Request};
use clavis_verifier::open_presentation;
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
    !needle.is_empty() && haystack.windows(needle.len()).any(|window| window == needle)
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

fn request(verifier_did: &str, verifier_x25519: [u8; 32], id: &str, nonce: [u8; 32]) -> Request {
    Request {
        id: id.into(),
        verifier_did: verifier_did.into(),
        verifier_x25519,
        fields: vec![ALLERGY_PATH.into()],
        nonce,
        purpose: "приём в поликлинике".into(),
        retention: "данное обращение".into(),
    }
}

fn timeouts(stream: &TcpStream) {
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
}

#[test]
fn tcp_release() {
    let verifier_identity = SigningKey::generate(&mut OsRng);
    let verifier_did =
        clavis_protocol::did_key_ed25519(&verifier_identity.verifying_key().to_bytes());
    let verifier = StaticSecret::random_from_rng(OsRng);
    let verifier_public = PublicKey::from(&verifier);
    let mut nonce = [0u8; 32];
    OsRng.fill_bytes(&mut nonce);

    let mut holder = Holder::start(claims()).unwrap();
    let device_did = holder.device_did();
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    assert_eq!(addr.ip(), Ipv4Addr::new(127, 0, 0, 1));
    assert_ne!(addr.port(), 0);

    let server = thread::spawn(move || {
        let (mut stream, peer) = listener.accept().unwrap();
        assert_eq!(peer.ip(), Ipv4Addr::new(127, 0, 0, 1));
        timeouts(&stream);
        holder.serve_connection(&mut stream).unwrap();
        holder
    });

    let mut stream = TcpStream::connect(addr).unwrap();
    stream.set_nodelay(true).unwrap();
    timeouts(&stream);

    let first = request(
        &verifier_did,
        verifier_public.to_bytes(),
        "req-clinic-allergy",
        nonce,
    );
    write_frame(&mut stream, &Frame::Request(first.clone())).unwrap();
    let sealed = match read_frame(&mut stream).unwrap() {
        Some(Frame::Presentation(sealed)) => sealed,
        other => panic!("expected one sealed presentation, got {other:?}"),
    };
    let wire = serde_json::to_vec(&sealed).unwrap();
    assert!(!contains(&wire, ALLERGY));
    assert!(!contains(&wire, WITHHELD));
    assert!(!contains(&sealed.ciphertext, ALLERGY));
    assert!(!contains(&sealed.ciphertext, WITHHELD));

    let opened = open_presentation(&sealed, &verifier).unwrap();
    assert_eq!(opened.nonce, nonce);
    assert_eq!(opened.request_id, first.id);
    assert_eq!(opened.disclosed.len(), 1);
    assert_eq!(opened.disclosed[0].path, ALLERGY_PATH);
    assert_eq!(opened.disclosed[0].value.as_deref(), Some(ALLERGY));
    assert!(opened
        .disclosed
        .iter()
        .all(|item| item.path != WITHHELD_PATH));
    assert!(verify_inclusion(&opened.disclosed[0], &opened.root));
    verify_holder(&opened).unwrap();
    assert_ne!(opened.holder_did, device_did);
    assert!(opened.holder_did.starts_with("did:key:z"));
    let pairwise_did = opened.holder_did.clone();

    let mut replay = first.clone();
    replay.id = "req-clinic-allergy-replay".into();
    assert_eq!(replay.nonce, nonce);
    write_frame(&mut stream, &Frame::Request(replay)).unwrap();
    match read_frame(&mut stream).unwrap() {
        Some(Frame::Reject(RejectReason::NonceReused)) => {}
        other => panic!("replay must not produce a presentation: {other:?}"),
    }

    let mut fresh = nonce;
    fresh[0] ^= 0xff;
    let next = request(
        &verifier_did,
        verifier_public.to_bytes(),
        "req-clinic-allergy-next",
        fresh,
    );
    write_frame(&mut stream, &Frame::Request(next)).unwrap();
    let sealed_again = match read_frame(&mut stream).unwrap() {
        Some(Frame::Presentation(sealed)) => sealed,
        other => panic!("a new nonce is a new presentation, got {other:?}"),
    };
    let opened_again = open_presentation(&sealed_again, &verifier).unwrap();
    assert_eq!(opened_again.nonce, fresh);
    assert_eq!(opened_again.disclosed[0].value.as_deref(), Some(ALLERGY));
    assert_eq!(opened_again.holder_did, pairwise_did);
    assert!(!contains(&sealed_again.ciphertext, WITHHELD));

    drop(stream);
    let holder = server.join().unwrap();
    assert_eq!(holder.presentations_built(), 2);
    assert!(holder.holds_pairwise_for(&verifier_did));
    assert!(holder.keys_remain_inside());
}
