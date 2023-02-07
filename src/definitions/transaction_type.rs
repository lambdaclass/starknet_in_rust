// The sender address used by default in declare transactions of version 0.
// DEFAULT_DECLARE_SENDER_ADDRESS = 1
pub(crate) const DEFAULT_DECLARE_SENDER_ADDRESS: u64 = 1;

#[derive(Debug, PartialEq, Clone)]
pub enum TransactionType {
    Declare,
    Deploy,
    DeployAccount,
    InitializeBlockInfo,
    InvokeFunction,
    L1Handler,
}
