#[derive(Debug, PartialEq, Clone)]
pub enum TransactionType {
    Declare,
    Deploy,
    DeployAccount,
    InitializeBlockInfo,
    InvokeFunction,
    L1Handler,
}
