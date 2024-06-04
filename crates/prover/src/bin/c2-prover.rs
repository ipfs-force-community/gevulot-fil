#![feature(array_chunks)]

use std::fs;
use std::fs::File;

use anyhow::Context;
use filecoin_proofs_api::seal;
use gevulot_common::WORKSPACE_PATH;
use gevulot_fil::codec::decode_from;
use gevulot_fil::workspace;
use gevulot_fil::C2Input;
use gevulot_shim::Task;
use gevulot_shim::TaskResult;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn main() -> Result<()> {
    gevulot_shim::run(run_task)
}

fn run_task(task: Task) -> Result<TaskResult> {
    println!("task: {:?}", task);
    let [_, input_filename] = task
        .args
        .array_chunks::<2>()
        .find(|[name, _]| name == "--input")
        .context("the --input <INPUT_FILENAME> argument were not provided")?;
    let [_, proof_output] = task
        .args
        .array_chunks::<2>()
        .find(|[name, _]| name == "--proof-output")
        .context("the --proof-output <PROOF_OUTPUT_FILENAME> argument were not provided")?;

    let (_, input_path) = task
        .get_task_files_path(WORKSPACE_PATH)
        .into_iter()
        .find(|(filename, _)| filename == input_filename)
        .with_context(|| format!("filename {} not found", input_filename))?;

    println!("----- {:?}", input_path.display());
    for res in std::fs::read_dir(input_path.parent().unwrap()).unwrap() {
        let e = res.unwrap();
        println!("{}", e.path().display()) 
    }
    
    let f = File::open(input_path).context("open the c2 input file")?;
    let c2_in: C2Input = decode_from(f).context("decode the c2 input data")?;

    match c2_in {
        C2Input::V0 {
            c1out,
            prover_id,
            sector_id,
        } => {
            let c2out = seal::seal_commit_phase2(c1out, prover_id, sector_id)
                .context("run seal_commit_phase2")?;
            fs::write(workspace(proof_output), &c2out.proof)
                .with_context(|| format!("write proof to {}", proof_output))?;
            task.result(c2out.proof, vec![proof_output.to_string()])
        }
    }
}
