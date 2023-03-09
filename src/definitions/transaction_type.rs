#[derive(Debug, PartialEq, Copy, Clone, Eq, Hash)]
pub enum TransactionType {
    Declare,
    Deploy,
    DeployAccount,
    InitializeBlockInfo,
    InvokeFunction,
    L1Handler,
}
