use std::collections::BTreeMap;
use std::path::PathBuf;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use base64::Engine;
use filecoin_proofs_api::ChallengeSeed;
use filecoin_proofs_api::Commitment;
use filecoin_proofs_api::ProverId;
use filecoin_proofs_api::RegisteredPoStProof;
use filecoin_proofs_api::SectorId;
use filecoin_proofs_api::SnarkProof;
use filecoin_proofs_api::StorageProofsError;
use forest_address::Address;
use gevulot_fil::calc_checksum;
use gevulot_fil::codec::encode;
use gevulot_fil::WindowPoStPhase2Input;
use gevulot_node::types::rpc::TxRpcPayload;
use gevulot_node::types::transaction::Payload;
use gevulot_node::types::transaction::ProgramData;
use gevulot_node::types::transaction::Workflow;
use gevulot_node::types::transaction::WorkflowStep;
use gevulot_node::types::Hash;
use gevulot_node::types::Transaction;
use serde::Deserialize;
use serde::Serialize;
use vc_processors::core::Processor;
use vc_processors::core::Task as VTask;
use windowpost_api::types::PrivateReplicaInfo;

use super::c2::ActorID;
use super::Gevulot;
use crate::util::block_on;

pub const STAGE_NAME_WINDOW_POST: &str = "windowpost";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PoStReplicaInfo {
    pub sector_id: SectorId,
    pub comm_r: Commitment,
    pub cache_dir: PathBuf,
    pub sealed_file: PathBuf,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WindowPoStOutput {
    pub proofs: Vec<SnarkProof>,
    pub faults: Vec<u64>,
}

/// Task of WindowPoSt
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WindowPoSt {
    pub miner_id: ActorID,
    pub proof_type: RegisteredPoStProof,
    pub replicas: Vec<PoStReplicaInfo>,
    pub seed: ChallengeSeed,
}

impl VTask for WindowPoSt {
    const STAGE: &'static str = STAGE_NAME_WINDOW_POST;
    type Output = WindowPoStOutput;
}

#[derive(Clone)]
pub struct WindowPoStProcessor {
    gevulot: Gevulot,
    prover_program: Hash,
    verifier_program: Hash,
}

impl WindowPoStProcessor {
    pub fn new(gevulot: Gevulot, prover_program: Hash, verifier_program: Hash) -> Self {
        Self {
            gevulot,
            prover_program,
            verifier_program,
        }
    }

    pub fn exec_wdp2(
        &self,
        wdp2_in: WindowPoStPhase2Input,
    ) -> Result<Vec<(RegisteredPoStProof, SnarkProof)>> {
        let wd_phase2_in_bytes =
            encode(&wdp2_in).context("encode the window post phase2 input data")?;
        let checksum = calc_checksum(&wd_phase2_in_bytes).to_string();

        self.gevulot
            .fs
            .write(&checksum, wd_phase2_in_bytes)
            .context("write window post phase2 input data to filestorage")?;

        let steps = vec![
            WorkflowStep {
                program: self.prover_program,
                args: vec![
                    String::from("--input"),
                    checksum.clone(),
                    String::from("--proof-output"),
                    String::from("proof.dat"),
                ],
                inputs: vec![ProgramData::Input {
                    file_name: checksum.clone(),
                    file_url: self.gevulot.fs.file_url(&checksum),
                    checksum: checksum.clone(),
                }],
            },
            WorkflowStep {
                program: self.verifier_program,
                args: vec![
                    String::from("--input"),
                    checksum.clone(),
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

                // return Ok(base64::engine::general_purpose::STANDARD.decode(verification)?);
            }
            Err(anyhow!("invalid payload"))
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

impl Processor<WindowPoSt> for WindowPoStProcessor {
    fn name(&self) -> String {
        "gevulot WindowPoSt".to_string()
    }

    fn process(&self, task: WindowPoSt) -> Result<<WindowPoSt as VTask>::Output> {
        let replicas = BTreeMap::from_iter(task.replicas.into_iter().map(|rep| {
            (
                rep.sector_id,
                PrivateReplicaInfo::new(
                    task.proof_type,
                    rep.comm_r,
                    rep.cache_dir,
                    rep.sealed_file,
                ),
            )
        }));

        let prover_id = to_prover_id(task.miner_id);
        match windowpost_api::generate_window_post_vanilla_proofs(&task.seed, &replicas, prover_id)
        {
            Ok((pub_sectors, vanilla_proofs)) => {
                let wdp2_in = WindowPoStPhase2Input::V0 {
                    proof_type: task.proof_type,
                    randomness: task.seed,
                    prover_id,
                    pub_sectors,
                    vanilla_proofs,
                };
                let proofs = self.exec_wdp2(wdp2_in)?;
                Ok(WindowPoStOutput {
                    proofs: proofs.into_iter().map(|x| x.1).collect(),
                    faults: vec![],
                })
            }
            Err(e) => match e.downcast_ref::<StorageProofsError>() {
                Some(StorageProofsError::FaultySectors(sectors)) => Ok(WindowPoStOutput {
                    proofs: vec![],
                    faults: sectors.iter().map(|id| (*id).into()).collect(),
                }),
                _ => Err(e),
            },
        }
    }
}

fn to_prover_id(miner_id: ActorID) -> ProverId {
    let mut prover_id: ProverId = Default::default();
    let actor_addr_payload = Address::new_id(miner_id).payload_bytes();
    prover_id[..actor_addr_payload.len()].copy_from_slice(actor_addr_payload.as_ref());
    prover_id
}
