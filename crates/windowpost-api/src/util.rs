use anyhow::Context;
use anyhow::Result;
use bellperson::groth16::Proof;
use blstrs::Bls12;
use filecoin_proofs::PoStConfig;

pub(crate) fn get_partitions_for_window_post(
    total_sector_count: usize,
    post_config: &PoStConfig,
) -> Option<usize> {
    let partitions = (total_sector_count as f32 / post_config.sector_count as f32).ceil() as usize;

    if partitions > 1 {
        Some(partitions)
    } else {
        None
    }
}

pub(crate) fn proofs_to_bytes(proofs: &[Proof<Bls12>]) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(Proof::<Bls12>::size());
    for proof in proofs {
        proof.write(&mut out).context("known allocation target")?;
    }
    Ok(out)
}
