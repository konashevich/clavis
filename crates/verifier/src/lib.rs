use clavis_protocol::{Presentation, SealedPresentation};
use x25519_dalek::StaticSecret;

pub fn open_presentation(
    sealed: &SealedPresentation,
    verifier_secret: &StaticSecret,
) -> Result<Presentation, clavis_protocol::Error> {
    clavis_protocol::open(sealed, verifier_secret)
}