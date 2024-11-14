use std::time::Duration;

use anyhow::Context;
use anyhow::Result;
use base64::Engine;
use filecoin_proofs_api::seal::SealCommitPhase1Output;
use filecoin_proofs_api::seal::SealCommitPhase2Output;
use filecoin_proofs_api::ProverId;
use filecoin_proofs_api::SectorId;
use gevulot_fil::calc_checksum;
use gevulot_fil::codec::encode;
use gevulot_fil::C2Input;
use gevulot_node::types::transaction::ProgramData;
use gevulot_node::types::transaction::WorkflowStep;
use gevulot_node::types::Hash;
use serde::Deserialize;
use serde::Serialize;
use tokio::time;
use vc_processors::core::Processor;
use vc_processors::core::Task as VTask;

use crate::filestorage::FileStorage;
use crate::gevulot::GevulotExecutor;
use crate::util::block_on;

pub const STAGE_NAME_C2: &str = "c2";

/// Identifier for Actors.
pub type ActorID = u64;

/// Task of commit phase2
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct C2 {
    pub c1out: SealCommitPhase1Output,
    pub prover_id: ProverId,
    pub sector_id: SectorId,
    pub miner_id: ActorID,
}

impl VTask for C2 {
    const STAGE: &'static str = STAGE_NAME_C2;
    type Output = SealCommitPhase2Output;
}

#[derive(Clone)]
pub struct C2Processor<G> {
    gevulot_executor: G,
    prover_program: Hash,
    verifier_program: Hash,
    fs: FileStorage,
}

impl<G: GevulotExecutor> C2Processor<G> {
    pub fn new(
        gevulot_executor: G,
        prover_program: Hash,
        verifier_program: Hash,
        fs: FileStorage,
    ) -> Self {
        Self {
            gevulot_executor,
            prover_program,
            verifier_program,
            fs,
        }
    }

    pub fn exec(&self, c2_in: C2Input) -> Result<Vec<u8>> {
        let c2_in_bytes = encode(&c2_in).context("encode the c2 input data")?;
        let checksum = calc_checksum(&c2_in_bytes).to_string();
        let vm_path = format!("/workspace/{checksum}");
        self.fs
            .write(&checksum, c2_in_bytes)
            .context("write c2 input data to filestorage")?;

        let steps = vec![
            WorkflowStep {
                program: self.prover_program,
                args: vec![
                    String::from("--input"),
                    vm_path.clone(),
                    String::from("--proof-output"),
                    String::from("proof.dat"),
                ],
                inputs: vec![ProgramData::Input {
                    file_name: vm_path.clone(),
                    file_url: self.fs.file_url(&checksum),
                    checksum: checksum.clone(),
                }],
            },
            WorkflowStep {
                program: self.verifier_program,
                args: vec![
                    String::from("--input"),
                    vm_path.clone(),
                    String::from("--proof"),
                    String::from("proof.dat"),
                ],
                inputs: vec![ProgramData::Output {
                    source_program: self.prover_program,
                    file_name: "proof.dat".to_string(),
                }],
            },
        ];

        block_on(async {
            let hash = self
                .gevulot_executor
                .run_program(steps)
                .await
                .context("run program")?;
            let mut interval = time::interval(Duration::from_secs(5));
            time::timeout(Duration::from_mins(60), async {
                loop {
                    interval.tick().await;

                    if let Some(proof_string) = self.gevulot_executor.query_proof(&hash).await? {
                        let proof =
                            base64::engine::general_purpose::STANDARD.decode(proof_string)?;
                        return Ok(proof);
                    }
                }
            })
            .await
            .context("timed out")?
        })
    }
}

impl<G: GevulotExecutor + Send + Sync> Processor<C2> for C2Processor<G> {
    fn name(&self) -> String {
        "gevulot C2".to_string()
    }

    fn process(&self, task: C2) -> Result<<C2 as VTask>::Output> {
        let c2_in = C2Input::V0 {
            c1out: task.c1out,
            prover_id: task.prover_id,
            sector_id: task.sector_id,
        };

        let proof = self.exec(c2_in)?;
        Ok(SealCommitPhase2Output { proof })
    }
}
