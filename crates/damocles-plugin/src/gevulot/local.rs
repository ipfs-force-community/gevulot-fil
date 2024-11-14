use std::collections::HashMap;
use std::sync::Arc;

use anyhow::anyhow;
use anyhow::Context;
use anyhow::Result;
use async_trait::async_trait;
use filecoin_proofs_api::seal;
use gevulot_fil::codec::decode;
use gevulot_fil::C2Input;
use gevulot_node::types::transaction::ProgramData;
use gevulot_node::types::transaction::WorkflowStep;
use gevulot_node::types::Hash;
use hex::ToHex;
use tokio::sync::Mutex;
use tokio::task::spawn_blocking;

use super::GevulotExecutor;
use crate::filestorage::FileStorage;

#[derive(Clone)]
pub struct GevulotLocalExecutor {
    proofs: Arc<Mutex<HashMap<Hash, String>>>,
    fs: FileStorage,
}

impl GevulotLocalExecutor {
    pub fn new(fs: FileStorage) -> Self {
        Self {
            proofs: Arc::new(Mutex::new(HashMap::new())),
            fs,
        }
    }
}

#[async_trait]
impl GevulotExecutor for GevulotLocalExecutor {
    async fn run_program(&self, steps: Vec<WorkflowStep>) -> Result<Hash> {
        let program_data = steps[0].inputs[0].clone();
        let fs = self.fs.clone();
        let proof = spawn_blocking(move || {
            let c2_input_data = match program_data {
                ProgramData::Input { file_name, .. } => fs.read_file(&file_name)?,
                _ => {
                    return Err(anyhow!("invlid workflow"));
                }
            };

            let c2_in: C2Input = decode(&c2_input_data).context("decode the c2 input data")?;

            match c2_in {
                C2Input::V0 {
                    c1out,
                    prover_id,
                    sector_id,
                } => {
                    let c2out = seal::seal_commit_phase2(c1out, prover_id, sector_id)
                        .context("run seal_commit_phase2")?;
                    Ok(c2out.proof.encode_hex())
                }
            }
        })
        .await
        .expect("c2 panic")?;

        let hash = Hash::random(&mut rand::thread_rng());
        self.proofs.lock().await.insert(hash, proof);
        Ok(hash)
    }

    async fn query_proof(&self, hash: &Hash) -> Result<Option<String>> {
        Ok(self.proofs.lock().await.get(hash).map(ToOwned::to_owned))
    }
}
