use cairo_vm::felt::Felt252;
use sha3::Keccak256;

use crate::definitions::constants;


/// A variant of eth-keccak that computes a value that fits in a StarkNet field element.
pub fn starknet_keccak(data: &[u8]) -> Felt252 {
    let mut hasher = Keccak256::default();
    hasher.update(data);
    let mut result = hasher.finalize();

    // Truncate result to 250 bits.
    *result.first_mut().unwrap() &= 3;
    Felt252::from_bytes_be(&result)
}

/// Returns an entry point selector, given its name.
pub fn selector_from_name(entry_point_name: &str) -> Felt252 {
    static DEFAULT_ENTRY_POINTS: [&str; 2] =
        [constants::DEFAULT_ENTRY_POINT_NAME, constants::DEFAULT_L1_ENTRY_POINT_NAME];

    // The default entry points selector is not being mapped in the usual way in order to save
    // computations in the OS, and to avoid encoding the default entry point names there.
    if DEFAULT_ENTRY_POINTS.contains(&entry_point_name) {
        constants::DEFAULT_ENTRY_POINT_SELECTOR.clone()
    } else {
        starknet_keccak(entry_point_name.as_bytes())
    }
}

/// Returns the storage address of a StarkNet storage variable given its name and arguments.
pub fn get_storage_var_address(
    storage_var_name: &str,
    args: &[StarkFelt],
) -> Result<StorageKey, StarknetApiError> {
    let storage_var_name_hash = starknet_keccak(storage_var_name.as_bytes());
    let storage_var_name_hash = felt_to_stark_felt(&storage_var_name_hash);

    let storage_key_hash =
        args.iter().fold(storage_var_name_hash, |res, arg| pedersen_hash(&res, arg));

    let storage_key = stark_felt_to_felt(storage_key_hash)
        .mod_floor(&Felt252::from_bytes_be(&L2_ADDRESS_UPPER_BOUND.to_bytes_be()));

    StorageKey::try_from(felt_to_stark_felt(&storage_key))
}

/// Gets storage keys for a Uint256 storage variable.
pub fn get_uint256_storage_var_addresses(
    storage_var_name: &str,
    args: &[StarkFelt],
) -> Result<(StorageKey, StorageKey), StarknetApiError> {
    let low_key = get_storage_var_address(storage_var_name, args)?;
    // TODO(Dori, 1/7/2023): When a standard representation for large integers is set, there may
    //   be a better way to add 1 to the key.
    let high_key = StorageKey(PatriciaKey::try_from(StarkFelt::from(
        FieldElement::from(*low_key.0.key()) + FieldElement::ONE,
    ))?);
    Ok((low_key, high_key))
}

pub fn get_erc20_balance_var_addresses(
    contract_address: &ContractAddress,
) -> Result<(StorageKey, StorageKey), StarknetApiError> {
    get_uint256_storage_var_addresses("ERC20_balances", &[*contract_address.0.key()])
}
