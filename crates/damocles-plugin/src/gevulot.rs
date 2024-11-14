use anyhow::Result;
use async_trait::async_trait;
use gevulot_node::types::transaction::WorkflowStep;
use gevulot_node::types::Hash;

pub mod local;
pub mod rpc;

#[async_trait]
pub trait GevulotExecutor {
    async fn run_program(&self, steps: Vec<WorkflowStep>) -> Result<Hash>;
    async fn query_proof(&self, hash: &Hash) -> Result<Option<String>>;
}

#[derive(Debug, Clone)]
pub enum Either<L, R> {
    Left(L),
    Right(R),
}

#[async_trait]
impl<L, R> GevulotExecutor for Either<L, R>
where
    L: GevulotExecutor + Sync,
    R: GevulotExecutor + Sync,
{
    async fn run_program(&self, steps: Vec<WorkflowStep>) -> Result<Hash> {
        match self {
            Either::Left(left) => left.run_program(steps).await,
            Either::Right(right) => right.run_program(steps).await,
        }
    }
    async fn query_proof(&self, hash: &Hash) -> Result<Option<String>> {
        match self {
            Either::Left(left) => left.query_proof(hash).await,
            Either::Right(right) => right.query_proof(hash).await,
        }
    }
}
