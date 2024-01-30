pub mod current;
pub mod deprecated;
use cairo_vm::Felt252;

#[derive(Debug)]
/// Enum representing the different types of transaction hash prefixes.
pub enum TransactionHashPrefix {
    Declare,
    Deploy,
    DeployAccount,
    Invoke,
    L1Handler,
}

// Returns the associated prefix value for a given transaction type.
impl TransactionHashPrefix {
    fn get_prefix(&self) -> Felt252 {
        match self {
            TransactionHashPrefix::Declare => Felt252::from_dec_str("28258975365558885").unwrap(),
            TransactionHashPrefix::Deploy => Felt252::from_dec_str("110386840629113").unwrap(),
            TransactionHashPrefix::DeployAccount => {
                Felt252::from_dec_str("2036277798190617858034555652763252").unwrap()
            }
            TransactionHashPrefix::Invoke => Felt252::from_dec_str("115923154332517").unwrap(),
            TransactionHashPrefix::L1Handler => {
                Felt252::from_dec_str("510926345461491391292786").unwrap()
            }
        }
    }
}
