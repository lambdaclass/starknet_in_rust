use crate::{
    core::contract_address::{compute_deprecated_class_hash, compute_sierra_class_hash},
    definitions::constants::CONSTRUCTOR_ENTRY_POINT_SELECTOR,
    hash_utils::compute_hash_on_elements,
    services::api::contract_classes::deprecated_contract_class::ContractClass,
    syscalls::syscall_handler_errors::SyscallHandlerError,
    utils::Address,
};
use cairo_lang_starknet::contract_class::ContractClass as SierraContractClass;
use cairo_vm::felt::{felt_str, Felt252};
use num_traits::Zero;

#[derive(Debug)]
pub enum TransactionHashPrefix {
    Declare,
    Deploy,
    DeployAccount,
    Invoke,
    L1Handler,
}

impl TransactionHashPrefix {
    fn get_prefix(&self) -> Felt252 {
        match self {
            TransactionHashPrefix::Declare => felt_str!("28258975365558885"),
            TransactionHashPrefix::Deploy => felt_str!("110386840629113"),
            TransactionHashPrefix::DeployAccount => felt_str!("2036277798190617858034555652763252"),
            TransactionHashPrefix::Invoke => felt_str!("115923154332517"),
            TransactionHashPrefix::L1Handler => felt_str!("510926345461491391292786"),
        }
    }
}

/// Calculates the transaction hash in the StarkNet network - a unique identifier of the
/// transaction.
/// The transaction hash is a hash chain of the following information:
///    1. A prefix that depends on the transaction type.
///    2. The transaction's version.
///    3. Contract address.
///    4. Entry point selector.
///    5. A hash chain of the calldata.
///    6. The transaction's maximum fee.
///    7. The network's chain ID.
/// Each hash chain computation begins with 0 as initialization and ends with its length appended.
/// The length is appended in order to avoid collisions of the following kind:
/// ```txt
///     H([x,y,z]) = h(h(x,y),z) = H([w, z]) where w = h(x,y)
/// ```
#[allow(clippy::too_many_arguments)]
pub fn calculate_transaction_hash_common(
    tx_hash_prefix: TransactionHashPrefix,
    version: Felt252,
    contract_address: &Address,
    entry_point_selector: Felt252,
    calldata: &[Felt252],
    max_fee: u128,
    chain_id: Felt252,
    additional_data: &[Felt252],
) -> Result<Felt252, SyscallHandlerError> {
    let calldata_hash = compute_hash_on_elements(calldata)?;

    let mut data_to_hash: Vec<Felt252> = vec![
        tx_hash_prefix.get_prefix(),
        version,
        contract_address.0.clone(),
        entry_point_selector,
        calldata_hash,
        max_fee.into(),
        chain_id,
    ];

    data_to_hash.extend(additional_data.iter().cloned());

    compute_hash_on_elements(&data_to_hash)
}

pub fn calculate_deploy_transaction_hash(
    version: Felt252,
    contract_address: &Address,
    constructor_calldata: &[Felt252],
    chain_id: Felt252,
) -> Result<Felt252, SyscallHandlerError> {
    calculate_transaction_hash_common(
        TransactionHashPrefix::Deploy,
        version,
        contract_address,
        CONSTRUCTOR_ENTRY_POINT_SELECTOR.clone(),
        constructor_calldata,
        0, // Considered 0 for Deploy transaction hash calculation purposes.
        chain_id,
        &[],
    )
}

#[allow(clippy::too_many_arguments)]
pub fn calculate_deploy_account_transaction_hash(
    version: Felt252,
    contract_address: &Address,
    class_hash: Felt252,
    constructor_calldata: &[Felt252],
    max_fee: u128,
    nonce: Felt252,
    salt: Felt252,
    chain_id: Felt252,
) -> Result<Felt252, SyscallHandlerError> {
    let mut calldata: Vec<Felt252> = vec![class_hash, salt];
    calldata.extend_from_slice(constructor_calldata);

    calculate_transaction_hash_common(
        TransactionHashPrefix::DeployAccount,
        version,
        contract_address,
        Felt252::zero(),
        &calldata,
        max_fee,
        chain_id,
        &[nonce],
    )
}

pub fn calculate_declare_transaction_hash(
    contract_class: &ContractClass,
    chain_id: Felt252,
    sender_address: &Address,
    max_fee: u128,
    version: Felt252,
    nonce: Felt252,
) -> Result<Felt252, SyscallHandlerError> {
    let class_hash = compute_deprecated_class_hash(contract_class)
        .map_err(|_| SyscallHandlerError::FailToComputeHash)?;

    let (calldata, additional_data) = if !version.is_zero() {
        (vec![class_hash], vec![nonce])
    } else {
        (Vec::new(), vec![class_hash])
    };

    calculate_transaction_hash_common(
        TransactionHashPrefix::Declare,
        version,
        sender_address,
        Felt252::zero(),
        &calldata,
        max_fee,
        chain_id,
        &additional_data,
    )
}

// ----------------------------
//      V2 Hash Functions
// ----------------------------

pub fn calculate_declare_v2_transaction_hash(
    contract_class: &SierraContractClass,
    compiled_class_hash: Felt252,
    chain_id: Felt252,
    sender_address: &Address,
    max_fee: u128,
    version: Felt252,
    nonce: Felt252,
) -> Result<Felt252, SyscallHandlerError> {
    let class_hash = compute_sierra_class_hash(contract_class)
        .map_err(|_| SyscallHandlerError::FailToComputeHash)?;

    let calldata = [class_hash].to_vec();
    let additional_data = [nonce, compiled_class_hash].to_vec();

    calculate_transaction_hash_common(
        TransactionHashPrefix::Declare,
        version,
        sender_address,
        Felt252::zero(),
        &calldata,
        max_fee,
        chain_id,
        &additional_data,
    )
}

#[cfg(test)]
mod tests {
    use cairo_vm::felt::felt_str;
    use coverage_helper::test;

    use crate::definitions::block_context::StarknetChainId;

    use super::*;

    #[test]
    fn calculate_transaction_hash_common_test() {
        let tx_hash_prefix = TransactionHashPrefix::Declare;
        let version = 0.into();
        let contract_address = Address(42.into());
        let entry_point_selector = 100.into();
        let calldata = vec![540.into(), 338.into()];
        let max_fee = 10;
        let chain_id = 1.into();
        let additional_data: Vec<Felt252> = Vec::new();

        // Expected value taken from Python implementation of calculate_transaction_hash_common function
        let expected = felt_str!(
            "2401716064129505935860131145275652294383308751137512921151718435935971973354"
        );

        let result = calculate_transaction_hash_common(
            tx_hash_prefix,
            version,
            &contract_address,
            entry_point_selector,
            &calldata,
            max_fee,
            chain_id,
            &additional_data,
        )
        .unwrap();

        assert_eq!(result, expected);
    }

    #[test]
    fn calculate_declare_hash_test() {
        let chain_id = StarknetChainId::MainNet;
        let sender_address = Address(felt_str!(
            "78963962122521774108119849325604561253807220406669671815499681746608877924"
        ));
        let max_fee = 30580718124600;
        let version = 1.into();
        let nonce = 3746.into();
        let class_hash = felt_str!(
            "1935775813346111469198021973672033051732472907985289186515250543849860001197"
        );

        let (calldata, additional_data) = (vec![class_hash], vec![nonce]);

        let tx = calculate_transaction_hash_common(
            TransactionHashPrefix::Declare,
            version,
            &sender_address,
            Felt252::zero(),
            &calldata,
            max_fee,
            chain_id.to_felt(),
            &additional_data,
        )
        .unwrap();

        assert_eq!(
            tx,
            felt_str!(
                "446404108171603570739811156347043235876209711235222547918688109133687877504"
            )
        )
    }
}
