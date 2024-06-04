use std::sync::Arc;

use anyhow::anyhow;
use anyhow::Result;
use gevulot_fil::SecretKey;
use gevulot_node::rpc_client::RpcClient;
use gevulot_node::types::transaction::Created;
use gevulot_node::types::Hash;
use gevulot_node::types::Transaction;
use zeroize::Zeroizing;

use crate::filestorage::FileStorage;

pub mod c2;
pub mod windowpost;

#[derive(Clone)]
pub struct Gevulot {
    client: Arc<RpcClient>,
    key: Zeroizing<SecretKey>,
    fs: FileStorage,
}

impl Gevulot {
    pub fn new(clint: Arc<RpcClient>, key: Zeroizing<SecretKey>, fs: FileStorage) -> Self {
        Self {
            client: clint,
            key,
            fs,
        }
    }

    async fn send_transaction(&self, tx: &Transaction<Created>) -> Result<Hash> {
        self.client
            .send_transaction(tx)
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
}
