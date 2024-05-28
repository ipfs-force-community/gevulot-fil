use std::collections::BTreeMap;

use anyhow::bail;
use anyhow::ensure;
use anyhow::Result;
use filecoin_hashers::Hasher;
use filecoin_proofs::types::ChallengeSeed;
use filecoin_proofs::types::PrivateReplicaInfo;
use filecoin_proofs::types::ProverId;
use filecoin_proofs::types::SnarkProof;
use filecoin_proofs::with_shape;
use filecoin_proofs::DefaultTreeDomain;
use filecoin_proofs::PoStType;
use filecoin_proofs::SectorShape2KiB;
use filecoin_proofs::SectorShape32GiB;
use filecoin_proofs::SectorShape512MiB;
use filecoin_proofs::SectorShape64GiB;
use filecoin_proofs::SectorShape8MiB;
use filecoin_proofs::VanillaProof as RawVanillaPoStProof;
use filecoin_proofs_api::RegisteredPoStProof;
use serde::Deserialize;
use serde::Serialize;
use storage_proofs_core::merkle::MerkleTreeTrait;
use storage_proofs_core::sector::SectorId;
use storage_proofs_post::fallback::PublicSector;

mod caches;
mod proof;
mod types;
mod util;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum VanillaPoStProofs {
    PoSt2KiBV1(Vec<RawVanillaPoStProof<SectorShape2KiB>>),
    PoSt8MiBV1(Vec<RawVanillaPoStProof<SectorShape8MiB>>),
    PoSt512MiBV1(Vec<RawVanillaPoStProof<SectorShape512MiB>>),
    PoSt32GiBV1(Vec<RawVanillaPoStProof<SectorShape32GiB>>),
    PoSt64GiBV1(Vec<RawVanillaPoStProof<SectorShape64GiB>>),
}

impl VanillaPoStProofs {
    pub fn try_from_raw<Tree: 'static + MerkleTreeTrait>(
        mut raw_proofs: Vec<RawVanillaPoStProof<Tree>>,
    ) -> Result<Self> {
        unsafe {
            Ok(if typeid::of::<Tree>() == typeid::of::<SectorShape2KiB>() {
                VanillaPoStProofs::PoSt2KiBV1(Vec::from_raw_parts(
                    raw_proofs.as_mut_ptr().cast(),
                    raw_proofs.len(),
                    raw_proofs.capacity(),
                ))
            } else if typeid::of::<Tree>() == typeid::of::<SectorShape8MiB>() {
                VanillaPoStProofs::PoSt8MiBV1(Vec::from_raw_parts(
                    raw_proofs.as_mut_ptr().cast(),
                    raw_proofs.len(),
                    raw_proofs.capacity(),
                ))
            } else if typeid::of::<Tree>() == typeid::of::<SectorShape512MiB>() {
                VanillaPoStProofs::PoSt512MiBV1(Vec::from_raw_parts(
                    raw_proofs.as_mut_ptr().cast(),
                    raw_proofs.len(),
                    raw_proofs.capacity(),
                ))
            } else if typeid::of::<Tree>() == typeid::of::<SectorShape32GiB>() {
                VanillaPoStProofs::PoSt32GiBV1(Vec::from_raw_parts(
                    raw_proofs.as_mut_ptr().cast(),
                    raw_proofs.len(),
                    raw_proofs.capacity(),
                ))
            } else if typeid::of::<Tree>() == typeid::of::<SectorShape64GiB>() {
                VanillaPoStProofs::PoSt32GiBV1(Vec::from_raw_parts(
                    raw_proofs.as_mut_ptr().cast(),
                    raw_proofs.len(),
                    raw_proofs.capacity(),
                ))
            } else {
                bail!("invalid proofs provided")
            })
        }
    }

    pub fn try_into_raw<Tree: 'static + MerkleTreeTrait>(
        self,
    ) -> Result<Vec<RawVanillaPoStProof<Tree>>> {
        Ok(unsafe {
            match self {
                VanillaPoStProofs::PoSt2KiBV1(mut x)
                    if typeid::of::<Tree>() == typeid::of::<SectorShape2KiB>() =>
                {
                    Vec::from_raw_parts(x.as_mut_ptr().cast(), x.len(), x.capacity())
                }
                VanillaPoStProofs::PoSt8MiBV1(mut x)
                    if typeid::of::<Tree>() == typeid::of::<SectorShape8MiB>() =>
                {
                    Vec::from_raw_parts(x.as_mut_ptr().cast(), x.len(), x.capacity())
                }
                VanillaPoStProofs::PoSt512MiBV1(mut x)
                    if typeid::of::<Tree>() == typeid::of::<SectorShape512MiB>() =>
                {
                    Vec::from_raw_parts(x.as_mut_ptr().cast(), x.len(), x.capacity())
                }
                VanillaPoStProofs::PoSt32GiBV1(mut x)
                    if typeid::of::<Tree>() == typeid::of::<SectorShape32GiB>() =>
                {
                    Vec::from_raw_parts(x.as_mut_ptr().cast(), x.len(), x.capacity())
                }
                VanillaPoStProofs::PoSt64GiBV1(mut x)
                    if typeid::of::<Tree>() == typeid::of::<SectorShape64GiB>() =>
                {
                    Vec::from_raw_parts(x.as_mut_ptr().cast(), x.len(), x.capacity())
                }
                _ => {
                    bail!("invalid proofs provided")
                }
            }
        })
    }
}

/// Generates a Window Proof-of-Spacetime.
///
/// # Arguments
/// * `randomness` - Random seed value for PoSt challenge.
/// * `replicas` - Replica to generate proof for.
/// * `prover_id` - Unique ID of the storage provider.
///
/// Returns [`SnarkProof`] for challenge.
pub fn generate_window_post_vanilla_proofs(
    proof_type: RegisteredPoStProof,
    randomness: &ChallengeSeed,
    replicas: &BTreeMap<SectorId, crate::types::PrivateReplicaInfo>,
    prover_id: ProverId,
) -> Result<(Vec<PublicSector<DefaultTreeDomain>>, VanillaPoStProofs)> {
    ensure!(!replicas.is_empty(), "no replicas supplied");
    let registered_post_proof_type_v1 = replicas
        .values()
        .next()
        .map(|v| v.registered_proof)
        .expect("replica map failure");
    ensure!(
        registered_post_proof_type_v1.typ() == PoStType::Window,
        "invalid post type provided"
    );

    with_shape!(
        u64::from(registered_post_proof_type_v1.sector_size()),
        generate_window_post_vanilla_proofs_inner,
        proof_type,
        randomness,
        replicas,
        prover_id,
    )
}

fn generate_window_post_vanilla_proofs_inner<Tree: 'static + MerkleTreeTrait>(
    proof_type: RegisteredPoStProof,
    randomness: &ChallengeSeed,
    replicas: &BTreeMap<SectorId, crate::types::PrivateReplicaInfo>,
    prover_id: ProverId,
) -> Result<(Vec<PublicSector<DefaultTreeDomain>>, VanillaPoStProofs)> {
    let mut replicas_v1 = BTreeMap::new();

    for (id, info) in replicas.iter() {
        let crate::types::PrivateReplicaInfo {
            registered_proof,
            comm_r,
            cache_dir,
            replica_path,
        } = info;

        ensure!(
            registered_proof == &proof_type,
            "can only generate the same kind of PoSt"
        );
        let info_v1 =
            PrivateReplicaInfo::<Tree>::new(replica_path.clone(), *comm_r, cache_dir.into())?;

        replicas_v1.insert(*id, info_v1);
    }

    ensure!(!replicas_v1.is_empty(), "missing v1 replicas");
    let post_config = proof_type.as_v1_config();
    let (mut pub_sectors, raw_vanilla_proofs) = proof::generate_window_post_vanilla_proofs(
        &post_config,
        randomness,
        &replicas_v1,
        prover_id,
    )?;

    Ok((
        unsafe {
            Vec::from_raw_parts(
                pub_sectors.as_mut_ptr().cast(),
                pub_sectors.len(),
                pub_sectors.capacity(),
            )
        },
        VanillaPoStProofs::try_from_raw::<Tree>(raw_vanilla_proofs)?,
    ))
}

pub fn generate_window_post_snark_proof<Tree: 'static + MerkleTreeTrait>(
    proof_type: RegisteredPoStProof,
    randomness: &ChallengeSeed,
    prover_id: ProverId,
    pub_sectors: Vec<PublicSector<DefaultTreeDomain>>,
    vanilla_proofs: VanillaPoStProofs,
) -> Result<SnarkProof> {
    with_shape!(
        u64::from(proof_type.sector_size()),
        generate_window_post_snark_proof_inner,
        proof_type,
        randomness,
        prover_id,
        pub_sectors,
        vanilla_proofs,
    )
}

fn generate_window_post_snark_proof_inner<Tree: 'static + MerkleTreeTrait>(
    proof_type: RegisteredPoStProof,
    randomness: &ChallengeSeed,
    prover_id: ProverId,
    mut pub_sectors: Vec<PublicSector<DefaultTreeDomain>>,
    vanilla_proofs: VanillaPoStProofs,
) -> Result<SnarkProof> {
    let post_config = proof_type.as_v1_config();

    let pub_sectors: Vec<PublicSector<<<Tree as MerkleTreeTrait>::Hasher as Hasher>::Domain>> = unsafe {
        Vec::from_raw_parts(
            pub_sectors.as_mut_ptr().cast(),
            pub_sectors.len(),
            pub_sectors.capacity(),
        )
    };
    let raw_vanilla_proofs = vanilla_proofs.try_into_raw::<Tree>()?;
    proof::generate_window_post_snark_proof::<Tree>(
        &post_config,
        randomness,
        prover_id,
        pub_sectors,
        raw_vanilla_proofs,
    )
}
