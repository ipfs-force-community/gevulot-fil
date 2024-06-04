use std::path::Path;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::anyhow;
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
use gevulot_node::types::rpc::TxRpcPayload;
use gevulot_node::types::transaction::Payload;
use gevulot_node::types::transaction::ProgramData;
use gevulot_node::types::transaction::Workflow;
use gevulot_node::types::transaction::WorkflowStep;
use gevulot_node::types::Hash;
use gevulot_node::types::Transaction;
use serde::Deserialize;
use serde::Serialize;
use tokio::time;
use vc_processors::core::Processor;
use vc_processors::core::Task as VTask;

use super::Gevulot;
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
pub struct C2Processor {
    gevulot: Gevulot,
    prover_program: Hash,
    verifier_program: Hash,
}

impl C2Processor {
    pub fn new(gevulot: Gevulot, prover_program: Hash, verifier_program: Hash) -> Self {
        Self {
            gevulot,
            prover_program,
            verifier_program,
        }
    }

    pub fn exec(&self, c2_in: C2Input) -> Result<Vec<u8>> {
        let c2_in_bytes = encode(&c2_in).context("encode the c2 input data")?;
        let checksum = calc_checksum(&c2_in_bytes).to_string();
        let vm_path = format!("/workspace/{checksum}");
        self.gevulot
            .fs
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
                    file_url: self.gevulot.fs.file_url(&checksum),
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

        let tx = Transaction::new(
            Payload::Run {
                workflow: Workflow { steps },
            },
            self.gevulot.key.inner(),
        );

        block_on(async {
            let tx_hash = self
                .gevulot
                .send_transaction(&tx)
                .await
                .context("send transaction")?;

            let transaction = self.gevulot.client.get_transaction(&tx_hash).await.unwrap();
            println!("{:?}", transaction);

            if let TxRpcPayload::Verification { verification, .. } = transaction.payload {
                return Ok(base64::engine::general_purpose::STANDARD.decode(verification)?);
            }
            todo!();
            // let mut interval = time::interval(Duration::from_secs(2));
            // time::timeout(Duration::from_mins(60), async {
            //     loop {
            //         interval.tick().await;
            //         match self.client.get_transaction(&tx_hash).await {
            //             Ok(transaction) => match transaction.payload {
            //                 TxRpcPayload::Verification { verification, .. } => {
            //                     let proof = base64::engine::general_purpose::STANDARD
            //                         .decode(verification)?;
            //                     return Ok(proof);
            //                 }
            //                 _ => {
            //                     todo!()
            //                 }
            //             },
            //             Err(err) => {
            //                 warn!(error=?err, "failed to get transaction: {}", tx_hash);
            //             }
            //         }
            //     }
            // })
            // .await
            // .context("timed out")
        })
    }
}

impl Processor<C2> for C2Processor {
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
