/// TransactionType is an enum that represents the type of transaction.
///
/// It is used in the transaction header and in the transaction execution info.
#[derive(Debug, PartialEq, Copy, Clone, Eq, Hash)]
pub enum TransactionType {
    Declare,
    Deploy,
    DeployAccount,
    InitializeBlockInfo,
    InvokeFunction,
    L1Handler,
}

impl From<TransactionType> for u64 {
    /// Converts a [TransactionType] into a [u64].
    fn from(tx_type: TransactionType) -> Self {
        match tx_type {
            TransactionType::Declare => 0,
            TransactionType::Deploy => 1,
            TransactionType::DeployAccount => 2,
            TransactionType::InitializeBlockInfo => 3,
            TransactionType::InvokeFunction => 4,
            TransactionType::L1Handler => 5,
        }
    }
}
