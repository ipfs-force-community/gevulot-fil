use std::fs;
use std::fs::File;
use std::io;
use std::path::Path;

use anyhow::Context;
use anyhow::Result;
use filecoin_proofs_api::seal;
use gevulot_common::WORKSPACE_PATH;
use gevulot_fil::codec::decode_from;
use gevulot_fil::workspace;
use gevulot_fil::C2Input;
use gevulot_shim::Task;
use gevulot_shim::TaskResult;

fn main() -> Result<()> {
    let f = File::open("/dataset/c2-input-8MiB.bincode.zst").context("open the c2 input file")?;
    let c2_in: C2Input = decode_from(f).context("decode the c2 input data")?;
    let mut proof_output = "./out".to_string();
    match c2_in {
        C2Input::V0 {
            c1out,
            prover_id,
            sector_id,
        } => {
            let c2out = seal::seal_commit_phase2(c1out, prover_id, sector_id)
                .context("run seal_commit_phase2")?;
            fs::write(workspace(&proof_output), &c2out.proof)
                .with_context(|| format!("write proof to {}", proof_output))?;
            // task.result(c2out.proof, vec![proof_output.to_string()])
            println!("{:?}", c2out.proof);
        }
    }

    Ok(())
}
