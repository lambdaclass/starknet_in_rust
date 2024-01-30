pub mod current;
pub mod deprecated;
use cairo_vm::Felt252;
use lazy_static::lazy_static;

#[derive(Debug)]
/// Enum representing the different types of transaction hash prefixes.
pub enum TransactionHashPrefix {
    Declare,
    Deploy,
    DeployAccount,
    Invoke,
    L1Handler,
}

lazy_static! {
    static ref DECLARE_TX_HASH_PREFIX: Felt252 =
        Felt252::from_dec_str("28258975365558885").unwrap();
    static ref DEPLOY_TX_HASH_PREFIX: Felt252 = Felt252::from_dec_str("110386840629113").unwrap();
    static ref DEPLOY_ACCOUNT_TX_HASH_PREFIX: Felt252 =
        Felt252::from_dec_str("2036277798190617858034555652763252").unwrap();
    static ref INVOKE_TX_HASH_PREFIX: Felt252 = Felt252::from_dec_str("115923154332517").unwrap();
    static ref L1_HANDLER_TX_HASH_PREFIX: Felt252 =
        Felt252::from_dec_str("510926345461491391292786").unwrap();
}

// Returns the associated prefix value for a given transaction type.
impl TransactionHashPrefix {
    fn get_prefix(&self) -> Felt252 {
        match self {
            TransactionHashPrefix::Declare => *DECLARE_TX_HASH_PREFIX,
            TransactionHashPrefix::Deploy => *DEPLOY_TX_HASH_PREFIX,
            TransactionHashPrefix::DeployAccount => *DEPLOY_ACCOUNT_TX_HASH_PREFIX,
            TransactionHashPrefix::Invoke => *INVOKE_TX_HASH_PREFIX,
            TransactionHashPrefix::L1Handler => *L1_HANDLER_TX_HASH_PREFIX,
        }
    }
}
