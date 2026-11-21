//! Index, journal, and each container are sealed under their own 32-byte key.
//! A release names one container and returns that container's plaintext.

use crate::{open_bytes, seal_bytes, DataKeyWrap, Module, UnwrapFailed};

/// Name a release uses to choose one container.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ContainerId(pub [u8; 16]);

/// One document and the key that seals it. The key is not shared with another container.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Container {
    pub id: ContainerId,
    pub key: [u8; 32],
    pub plaintext: Vec<u8>,
}

/// Vault before the device module wraps its keys.
/// `index` holds card headers. Document bodies live in `containers`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Store {
    pub index_key: [u8; 32],
    pub journal_key: [u8; 32],
    pub index: Vec<u8>,
    pub journal: Vec<u8>,
    pub containers: Vec<Container>,
}

/// Ciphertext of an index, a journal, or one container. The sealing key is not stored here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedBody {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedContainer {
    pub id: ContainerId,
    pub key: DataKeyWrap,
    pub body: SealedBody,
}

/// Stored vault. The device module holds the only unwrap of each key.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedStore {
    pub index_key: DataKeyWrap,
    pub journal_key: DataKeyWrap,
    pub index: SealedBody,
    pub journal: SealedBody,
    pub containers: Vec<SealedContainer>,
}

/// Plaintext from the one container a release named.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OpenedContainer {
    pub id: ContainerId,
    pub plaintext: Vec<u8>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum OpenError {
    UnknownContainer,
    Sealed(UnwrapFailed),
}

pub fn seal_store(module: &impl Module, store: &Store) -> SealedStore {
    SealedStore {
        index_key: module.wrap(&store.index_key),
        journal_key: module.wrap(&store.journal_key),
        index: seal_body(&store.index_key, &store.index),
        journal: seal_body(&store.journal_key, &store.journal),
        containers: store
            .containers
            .iter()
            .map(|container| SealedContainer {
                id: container.id,
                key: module.wrap(&container.key),
                body: seal_body(&container.key, &container.plaintext),
            })
            .collect(),
    }
}

pub fn open_index(module: &impl Module, store: &SealedStore) -> Result<Vec<u8>, UnwrapFailed> {
    open_wrapped(module, &store.index_key, &store.index)
}

pub fn open_journal(module: &impl Module, store: &SealedStore) -> Result<Vec<u8>, UnwrapFailed> {
    open_wrapped(module, &store.journal_key, &store.journal)
}

/// Unwrap and open only the named container.
pub fn open_release(
    module: &impl Module,
    store: &SealedStore,
    id: ContainerId,
) -> Result<OpenedContainer, OpenError> {
    let container = store
        .containers
        .iter()
        .find(|container| container.id == id)
        .ok_or(OpenError::UnknownContainer)?;
    let plaintext =
        open_wrapped(module, &container.key, &container.body).map_err(OpenError::Sealed)?;
    Ok(OpenedContainer { id, plaintext })
}

pub fn open_body(key: &[u8; 32], body: &SealedBody) -> Result<Vec<u8>, UnwrapFailed> {
    open_bytes(key, &body.nonce, &body.ciphertext)
}

fn seal_body(key: &[u8; 32], plaintext: &[u8]) -> SealedBody {
    let sealed = seal_bytes(key, plaintext);
    SealedBody {
        nonce: sealed.nonce,
        ciphertext: sealed.ciphertext,
    }
}

fn open_wrapped(
    module: &impl Module,
    wrap: &DataKeyWrap,
    body: &SealedBody,
) -> Result<Vec<u8>, UnwrapFailed> {
    let mut key = module.unwrap(wrap)?;
    let opened = open_body(&key, body);
    key.fill(0);
    opened
}
