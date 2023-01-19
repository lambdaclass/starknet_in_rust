use crate::definitions::transaction_type::TransactionType;
use crate::utils::Address;
use felt::Felt;

pub struct InternalDeploy {
    hash_value: Felt,
    version: usize,
    contract_address: Address,
    contract_address_salt: Address,
    conctract_hash: Vec<u8>,
    constructor_calldata: Vec<Felt>,
    tx_type: TransactionType,
}
