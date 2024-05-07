#![feature(error_generic_member_access)]

use std::path::Path;
use std::path::PathBuf;

use anyhow::Result;
use filecoin_proofs_api::seal::SealCommitPhase1Output;
use filecoin_proofs_api::ProverId;
use filecoin_proofs_api::SectorId;
use gevulot_common::WORKSPACE_PATH;
use gevulot_node::types::Hash;
use serde::Deserialize;
use serde::Serialize;
use zeroize::Zeroize;
use zeroize::ZeroizeOnDrop;

pub mod codec;

/// Wrapper around a [libsecp256k1::SecretKey] that implements [Zeroize].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SecretKey(libsecp256k1::SecretKey);

impl SecretKey {
    pub fn parse_slice(p: &[u8]) -> Result<Self> {
        Ok(SecretKey(libsecp256k1::SecretKey::parse_slice(p)?))
    }

    pub fn inner(&self) -> &libsecp256k1::SecretKey {
        &self.0
    }
}

impl Zeroize for SecretKey {
    fn zeroize(&mut self) {
        let mut sk = libsecp256k1::SecretKey::default();
        std::mem::swap(&mut self.0, &mut sk);
        let mut sk: libsecp256k1::curve::Scalar = sk.into();
        sk.0.zeroize();
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.zeroize()
    }
}

impl ZeroizeOnDrop for SecretKey {}

impl TryFrom<Vec<u8>> for SecretKey {
    type Error = libsecp256k1::Error;

    fn try_from(mut value: Vec<u8>) -> Result<Self, Self::Error> {
        let sk = libsecp256k1::SecretKey::parse_slice(&value)?;
        value.zeroize();
        Ok(Self(sk))
    }
}

impl From<libsecp256k1::SecretKey> for SecretKey {
    fn from(value: libsecp256k1::SecretKey) -> Self {
        Self(value)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum C2Input {
    // V0 of the c2 input
    V0 {
        c1out: SealCommitPhase1Output,
        prover_id: ProverId,
        sector_id: SectorId,
    },
}

pub fn calc_checksum(data: &[u8]) -> Hash {
    let hash = blake3::hash(data);
    (&hash).into()
}

pub fn workspace(filename: impl AsRef<Path>) -> PathBuf {
    Path::new(WORKSPACE_PATH).join(filename)
}
