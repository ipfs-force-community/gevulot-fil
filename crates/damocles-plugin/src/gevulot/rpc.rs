use std::sync::Arc;

use anyhow::anyhow;
use anyhow::Result;
use async_trait::async_trait;
use gevulot_fil::SecretKey;
use gevulot_node::rpc_client::RpcClient;
use gevulot_node::types::rpc::TxRpcPayload;
use gevulot_node::types::transaction::Payload;
use gevulot_node::types::transaction::Workflow;
use gevulot_node::types::transaction::WorkflowStep;
use gevulot_node::types::Hash;
use gevulot_node::types::Transaction;
use zeroize::Zeroizing;

use super::GevulotExecutor;
use crate::filestorage::FileStorage;

#[derive(Clone)]
pub struct GevulotRpcExecutor {
    client: Arc<RpcClient>,
    key: Zeroizing<SecretKey>,
    _fs: FileStorage,
}

impl GevulotRpcExecutor {
    pub fn new(clint: Arc<RpcClient>, key: Zeroizing<SecretKey>, fs: FileStorage) -> Self {
        Self {
            client: clint,
            key,
            _fs: fs,
        }
    }
}

#[async_trait]
impl GevulotExecutor for GevulotRpcExecutor {
    async fn run_program(&self, steps: Vec<WorkflowStep>) -> Result<Hash> {
        let tx = Transaction::new(
            Payload::Run {
                workflow: Workflow { steps },
            },
            self.key.inner(),
        );

        self.client
            .send_transaction(&tx)
            .await
            .map_err(|err| anyhow!("error during send transaction to the node: {err}"))?;

        let read_tx = self
            .client
            .get_transaction(&tx.hash)
            .await
            .map_err(|err| anyhow!("error during send get_transaction from the node: {err}"))?;

        if tx.hash.to_string() != read_tx.hash {
            return Err(anyhow!(
                "Error get_transaction doesn't return the right tx send tx:{} read tx:{:?}",
                tx.hash,
                read_tx
            ));
        }

        Ok(tx.hash)
    }

    async fn query_proof(&self, tx_hash: &Hash) -> Result<Option<String>> {
        let tx = self
            .client
            .get_transaction(&tx_hash)
            .await
            .map_err(|err| anyhow!("error during send get_transaction from the node: {err}"))?;

        match tx.payload {
            TxRpcPayload::Proof { proof, .. } => Ok(Some(proof)),
            _ => Ok(None),
        }
    }
}
