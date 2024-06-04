use std::path::PathBuf;

use filecoin_proofs::Commitment;
use filecoin_proofs_api::RegisteredPoStProof;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PrivateReplicaInfo {
    /// The version of this replica.
    pub(crate) registered_proof: RegisteredPoStProof,
    /// The replica commitment.
    pub(crate) comm_r: Commitment,
    /// Contains sector-specific (e.g. Merkle trees) assets.
    pub(crate) cache_dir: PathBuf,
    /// Contains the replica.
    pub(crate) replica_path: PathBuf,
}

impl PrivateReplicaInfo {
    pub fn new(
        registered_proof: RegisteredPoStProof,
        comm_r: Commitment,
        cache_dir: PathBuf,
        replica_path: PathBuf,
    ) -> Self {
        PrivateReplicaInfo {
            registered_proof,
            comm_r,
            cache_dir,
            replica_path,
        }
    }
}
