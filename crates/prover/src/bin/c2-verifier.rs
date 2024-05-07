#![feature(array_chunks)]

use std::fs;
use std::fs::File;

use anyhow::anyhow;
use anyhow::Context;
use filecoin_proofs_api::seal;
use gevulot_common::WORKSPACE_PATH;
use gevulot_fil::codec::decode_from;
use gevulot_fil::C2Input;
use gevulot_shim::Task;
use gevulot_shim::TaskResult;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() -> Result<()> {
    gevulot_shim::run(run_task)
}

fn run_task(task: Task) -> Result<TaskResult> {
    let [_, input_filename] = task
        .args
        .array_chunks::<2>()
        .find(|[name, _]| name == "--input")
        .context("the --input <INPUT_FILENAME> argument were not provided")?;
    let [_, proof_filename] = task
        .args
        .array_chunks::<2>()
        .find(|[name, _]| name == "--proof")
        .context("the --proof <PROOF_FILENAME> argument were not provided")?;

    let files = task.get_task_files_path(WORKSPACE_PATH);

    let (_, input_path) = files
        .iter()
        .find(|(filename, _)| filename == input_filename)
        .with_context(|| format!("filename {} not found", input_filename))?;

    let (_, proof_path) = files
        .iter()
        .find(|(filename, _)| filename == proof_filename)
        .with_context(|| format!("filename {} not found", proof_filename))?;

    let f = File::open(input_path).context("open the c2 input file")?;
    let c2_in: C2Input = decode_from(f).context("decode the c2 input data")?;

    let proof =
        fs::read(&proof_path).with_context(|| format!("read proof: {}", proof_path.display()))?;

    match c2_in {
        C2Input::V0 {
            c1out,
            prover_id,
            sector_id,
        } => {
            seal::verify_seal(
                c1out.registered_proof,
                c1out.comm_r,
                c1out.comm_d,
                prover_id,
                sector_id,
                c1out.ticket,
                c1out.seed,
                &proof,
            )
            .and_then(|x| x.then_some(()).ok_or(anyhow!("invalid proof")))
            .context("verify seal")?;
            task.result(proof, vec![])
        }
    }
}
