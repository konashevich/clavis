//! Linux holder shell.
//!
//! A dynamic request arrives as one length-prefixed frame. The holder answers
//! with one sealed presentation and stores the nonce. The same nonce does not
//! build a second presentation. The device key stays behind [`clavis_holder::Module`].
//! The pairwise presentation key is per verifier and is not exported.

use std::collections::{HashMap, HashSet};
use std::io::{Read, Write};
use std::net::TcpStream;

use clavis_holder::{Module, PairwiseKey, TestModule};
use clavis_protocol::{Claim, Request, SealedPresentation};
use serde::{Deserialize, Serialize};

const MAX_FRAME: usize = 1024 * 1024;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Frame,
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(err) => write!(f, "{err}"),
            Error::Frame => write!(f, "frame rejected"),
        }
    }
}

impl std::error::Error for Error {}

pub fn boot() -> Result<(), clavis_holder::NoPlatformModule> {
    clavis_holder::boot(true)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "body", rename_all = "snake_case")]
pub enum Frame {
    Request(Request),
    Presentation(SealedPresentation),
    Reject(RejectReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RejectReason {
    NonceReused,
    Refused,
}

pub struct Holder {
    module: TestModule,
    pairwise: HashMap<String, PairwiseKey>,
    spent: HashSet<[u8; 32]>,
    claims: Vec<Claim>,
    built: usize,
}

impl Holder {
    pub fn start(claims: Vec<Claim>) -> Result<Self, clavis_holder::NoPlatformModule> {
        boot()?;
        Ok(Self {
            module: TestModule::generate(),
            pairwise: HashMap::new(),
            spent: HashSet::new(),
            claims,
            built: 0,
        })
    }

    pub fn device_did(&self) -> String {
        clavis_protocol::did_key_ed25519(&self.module.public_bytes())
    }

    pub fn presentations_built(&self) -> usize {
        self.built
    }

    pub fn holds_pairwise_for(&self, verifier_did: &str) -> bool {
        self.pairwise.contains_key(verifier_did)
    }

    pub fn keys_remain_inside(&self) -> bool {
        self.module.try_export().is_err()
            && self.pairwise.values().all(|key| key.try_export().is_err())
    }

    /// Read request frames until the peer closes the connection.
    pub fn serve_connection(&mut self, stream: &mut TcpStream) -> Result<(), Error> {
        stream.set_nodelay(true).map_err(Error::Io)?;
        loop {
            match read_frame(stream)? {
                None => return Ok(()),
                Some(frame) => {
                    let reply = self.reply(frame);
                    write_frame(stream, &reply)?;
                }
            }
        }
    }

    fn reply(&mut self, frame: Frame) -> Frame {
        let Frame::Request(request) = frame else {
            return Frame::Reject(RejectReason::Refused);
        };
        if !self.spent.insert(request.nonce) {
            return Frame::Reject(RejectReason::NonceReused);
        }
        let verifier_did = request.verifier_did.clone();
        if !self.pairwise.contains_key(&verifier_did) {
            self.pairwise
                .insert(verifier_did.clone(), PairwiseKey::generate());
        }
        let claims = self.claims.clone();
        let sealed = self
            .pairwise
            .get(&verifier_did)
            .expect("pairwise key")
            .release(&claims, &request);
        match sealed {
            Ok(sealed) => {
                self.built += 1;
                Frame::Presentation(sealed)
            }
            Err(_) => Frame::Reject(RejectReason::Refused),
        }
    }
}

pub fn write_frame(stream: &mut impl Write, frame: &Frame) -> Result<(), Error> {
    let payload = serde_json::to_vec(frame).map_err(|_| Error::Frame)?;
    if payload.is_empty() || payload.len() > MAX_FRAME {
        return Err(Error::Frame);
    }
    let len = (payload.len() as u32).to_be_bytes();
    stream.write_all(&len).map_err(Error::Io)?;
    stream.write_all(&payload).map_err(Error::Io)?;
    stream.flush().map_err(Error::Io)?;
    Ok(())
}

pub fn read_frame(stream: &mut impl Read) -> Result<Option<Frame>, Error> {
    let Some(len_buf) = read_prefix(stream)? else {
        return Ok(None);
    };
    let len = u32::from_be_bytes(len_buf) as usize;
    if len == 0 || len > MAX_FRAME {
        return Err(Error::Frame);
    }
    let mut payload = vec![0u8; len];
    read_exact(stream, &mut payload)?;
    serde_json::from_slice(&payload)
        .map(Some)
        .map_err(|_| Error::Frame)
}

fn read_prefix(stream: &mut impl Read) -> Result<Option<[u8; 4]>, Error> {
    let mut buf = [0u8; 4];
    let mut filled = 0;
    while filled < buf.len() {
        match stream.read(&mut buf[filled..]) {
            Ok(0) if filled == 0 => return Ok(None),
            Ok(0) => {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "short length",
                )));
            }
            Ok(n) => filled += n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(Error::Io(err)),
        }
    }
    Ok(Some(buf))
}

fn read_exact(stream: &mut impl Read, buf: &mut [u8]) -> Result<(), Error> {
    let mut filled = 0;
    while filled < buf.len() {
        match stream.read(&mut buf[filled..]) {
            Ok(0) => {
                return Err(Error::Io(std::io::Error::new(
                    std::io::ErrorKind::UnexpectedEof,
                    "short frame",
                )));
            }
            Ok(n) => filled += n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(Error::Io(err)),
        }
    }
    Ok(())
}
