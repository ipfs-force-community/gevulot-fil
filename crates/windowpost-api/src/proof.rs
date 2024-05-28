use std::collections::BTreeMap;

use anyhow::ensure;
use anyhow::Context;
use anyhow::Result;
use filecoin_hashers::Hasher;
use filecoin_proofs::as_safe_commitment;
use filecoin_proofs::parameters::window_post_setup_params;
use filecoin_proofs::types::ChallengeSeed;
use filecoin_proofs::types::PoStConfig;
use filecoin_proofs::types::PrivateReplicaInfo;
use filecoin_proofs::types::ProverId;
use filecoin_proofs::types::SnarkProof;
use filecoin_proofs::PoStType;
use filecoin_proofs::VanillaProof as RawVanillaPoStProof;
use rayon::prelude::IntoParallelRefIterator;
use rayon::prelude::ParallelIterator;
use storage_proofs_core::compound_proof::CompoundProof;
use storage_proofs_core::compound_proof::{self};
use storage_proofs_core::merkle::MerkleTreeTrait;
use storage_proofs_core::proof::ProofScheme;
use storage_proofs_core::sector::SectorId;
use storage_proofs_post::fallback::FallbackPoSt;
use storage_proofs_post::fallback::FallbackPoStCompound;
use storage_proofs_post::fallback::PrivateSector;
use storage_proofs_post::fallback::PublicSector;
use storage_proofs_post::fallback::{self};

use crate::caches::get_post_params;
use crate::util;
use crate::util::get_partitions_for_window_post;

type TreeDomain<Tree> = <<Tree as MerkleTreeTrait>::Hasher as Hasher>::Domain;

pub(crate) fn generate_window_post_vanilla_proofs<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    replicas: &BTreeMap<SectorId, PrivateReplicaInfo<Tree>>,
    prover_id: ProverId,
) -> Result<(
    Vec<PublicSector<TreeDomain<Tree>>>,
    Vec<RawVanillaPoStProof<Tree>>,
)> {
    ensure!(
        post_config.typ == PoStType::Window,
        "invalid post config type"
    );

    let randomness_safe = as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe = as_safe_commitment(&prover_id, "prover_id")?;

    let vanilla_params = window_post_setup_params(post_config);
    let partitions = get_partitions_for_window_post(replicas.len(), post_config);

    let sector_count = vanilla_params.sector_count;
    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions,
        priority: post_config.priority,
    };

    let pub_params: compound_proof::PublicParams<'_, FallbackPoSt<'_, Tree>> =
        FallbackPoStCompound::setup(&setup_params)?;

    let trees: Vec<_> = replicas
        .par_iter()
        .map(|(sector_id, replica)| {
            replica
                .merkle_tree(post_config.sector_size)
                .with_context(|| {
                    format!("generate_window_post: merkle_tree failed: {:?}", sector_id)
                })
        })
        .collect::<Result<_>>()?;

    let mut pub_sectors = Vec::with_capacity(sector_count);
    let mut priv_sectors = Vec::with_capacity(sector_count);

    for ((sector_id, replica), tree) in replicas.iter().zip(trees.iter()) {
        let comm_r = replica.safe_comm_r().with_context(|| {
            format!("generate_window_post: safe_comm_r failed: {:?}", sector_id)
        })?;
        let comm_c = replica.safe_comm_c();
        let comm_r_last = replica.safe_comm_r_last();

        pub_sectors.push(PublicSector {
            id: *sector_id,
            comm_r,
        });
        priv_sectors.push(PrivateSector {
            tree,
            comm_c,
            comm_r_last,
        });
    }

    let pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors: pub_sectors,
        k: None,
    };

    let priv_inputs = fallback::PrivateInputs::<Tree> {
        sectors: &priv_sectors,
    };

    let partition_count = match pub_params.partitions {
        None => 1,
        Some(0) => panic!("cannot specify zero partitions"),
        Some(k) => k,
    };

    // This will always run at least once, since there cannot be zero partitions.
    ensure!(partition_count > 0, "There must be partitions");

    let raw_vanilla_proof = <FallbackPoSt<'_, Tree> as ProofScheme<'_>>::prove_all_partitions(
        &pub_params.vanilla_params,
        &pub_inputs,
        &priv_inputs,
        partition_count,
    )?;

    Ok((pub_inputs.sectors, raw_vanilla_proof))
}

pub(crate) fn generate_window_post_snark_proof<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
    randomness: &ChallengeSeed,
    prover_id: ProverId,
    sectors: Vec<PublicSector<<<Tree as MerkleTreeTrait>::Hasher as Hasher>::Domain>>,
    vanilla_proofs: Vec<RawVanillaPoStProof<Tree>>,
) -> Result<SnarkProof> {
    let randomness_safe = as_safe_commitment(randomness, "randomness")?;
    let prover_id_safe = as_safe_commitment(&prover_id, "prover_id")?;

    let vanilla_params = window_post_setup_params(post_config);
    let partitions = get_partitions_for_window_post(vanilla_params.sector_count, post_config);

    let setup_params = compound_proof::SetupParams {
        vanilla_params,
        partitions,
        priority: post_config.priority,
    };

    let pub_params: compound_proof::PublicParams<'_, FallbackPoSt<'_, Tree>> =
        FallbackPoStCompound::setup(&setup_params)?;

    let groth_params = get_post_params::<Tree>(post_config)?;

    let pub_inputs = fallback::PublicInputs {
        randomness: randomness_safe,
        prover_id: prover_id_safe,
        sectors,
        k: None,
    };

    let groth_proofs = FallbackPoStCompound::<Tree>::circuit_proofs(
        &pub_inputs,
        vanilla_proofs,
        &pub_params.vanilla_params,
        &groth_params,
        pub_params.priority,
    )?;
    util::proofs_to_bytes(&groth_proofs)
}
