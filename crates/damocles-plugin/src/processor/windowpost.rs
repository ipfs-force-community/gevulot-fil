use std::collections::BTreeMap;
use std::path::PathBuf;
use std::time::Duration;

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
use gevulot_node::types::transaction::ProgramData;
use gevulot_node::types::transaction::WorkflowStep;
use gevulot_node::types::Hash;
use serde::Deserialize;
use serde::Serialize;
use tokio::time;
use vc_processors::core::Processor;
use vc_processors::core::Task as VTask;
use windowpost_api::types::PrivateReplicaInfo;

use super::c2::ActorID;
use crate::filestorage::FileStorage;
use crate::gevulot::GevulotExecutor;
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
pub struct WindowPoStProcessor<G> {
    gevulot_executor: G,
    prover_program: Hash,
    verifier_program: Hash,
    fs: FileStorage,
}

impl<G: GevulotExecutor> WindowPoStProcessor<G> {
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

    pub fn exec_wdp2(
        &self,
        wdp2_in: WindowPoStPhase2Input,
    ) -> Result<Vec<(RegisteredPoStProof, SnarkProof)>> {
        let wd_phase2_in_bytes =
            encode(&wdp2_in).context("encode the window post phase2 input data")?;
        let checksum = calc_checksum(&wd_phase2_in_bytes).to_string();

        self.fs
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
                    file_url: self.fs.file_url(&checksum),
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
                        let _proof =
                            base64::engine::general_purpose::STANDARD.decode(proof_string)?;
                        return Ok(vec![]);
                    }
                }
            })
            .await
            .context("timed out")?
        })
    }
}

impl<G: GevulotExecutor + Send + Sync> Processor<WindowPoSt> for WindowPoStProcessor<G> {
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
