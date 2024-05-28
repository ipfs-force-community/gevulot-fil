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
