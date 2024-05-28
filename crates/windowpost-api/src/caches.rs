use std::sync::Arc;

use anyhow::Result;
use filecoin_proofs::caches::lookup_groth_params;
use filecoin_proofs::parameters::window_post_public_params;
use filecoin_proofs::parameters::winning_post_public_params;
use filecoin_proofs::MerkleTreeTrait;
use filecoin_proofs::PoStConfig;
use filecoin_proofs::PoStType;
use rand::rngs::OsRng;
use storage_proofs_core::compound_proof::CompoundProof;
use storage_proofs_core::parameter_cache::Bls12GrothParams;
use storage_proofs_post::fallback::FallbackPoSt;
use storage_proofs_post::fallback::FallbackPoStCircuit;
use storage_proofs_post::fallback::FallbackPoStCompound;

pub(crate) fn get_post_params<Tree: 'static + MerkleTreeTrait>(
    post_config: &PoStConfig,
) -> Result<Arc<Bls12GrothParams>> {
    match post_config.typ {
        PoStType::Winning => {
            let post_public_params = winning_post_public_params::<Tree>(post_config)?;

            let parameters_generator = || {
                <FallbackPoStCompound<Tree> as CompoundProof<
                    FallbackPoSt<'_, Tree>,
                    FallbackPoStCircuit<Tree>,
                >>::groth_params::<OsRng>(None, &post_public_params)
                .map_err(Into::into)
            };

            Ok(lookup_groth_params(
                format!(
                    "WINNING_POST[{}]",
                    usize::from(post_config.padded_sector_size())
                ),
                parameters_generator,
            )?)
        }
        PoStType::Window => {
            let post_public_params = window_post_public_params::<Tree>(post_config)?;

            let parameters_generator = || {
                <FallbackPoStCompound<Tree> as CompoundProof<
                    FallbackPoSt<'_, Tree>,
                    FallbackPoStCircuit<Tree>,
                >>::groth_params::<OsRng>(None, &post_public_params)
                .map_err(Into::into)
            };

            Ok(lookup_groth_params(
                format!(
                    "Window_POST[{}]",
                    usize::from(post_config.padded_sector_size())
                ),
                parameters_generator,
            )?)
        }
    }
}
