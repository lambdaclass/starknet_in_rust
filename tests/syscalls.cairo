%lang starknet

from starkware.starknet.common.syscalls import get_block_number, get_block_timestamp, get_tx_info

func array_sum(len: felt, arr: felt*) -> felt {
    if (len == 0) {
        return 0;
    }

    let sum_of_rest = array_sum(len - 1, arr + 1);
    return arr[0] + sum_of_rest;
}

@external
func test_get_block_number{syscall_ptr: felt*}() -> (block_number: felt) {
    let block_number = get_block_number();

    return (block_number);
}

@external
func test_get_block_timestamp{syscall_ptr: felt*}() -> (block_timestamp: felt) {
    let block_timestamp = get_block_timestamp();

    return (block_timestamp);
}

@external
func test_get_tx_info{syscall_ptr: felt*}() -> (
    version: felt,
    account_contract_address: felt,
    max_fee: felt,
    signature_len: felt,
    signature_hash: felt,
    transaction_hash: felt,
    chain_id: felt,
) {
    alloc_locals;

    let (local tx_info) = get_tx_info();
    let signature_sum = array_sum(tx_info.signature_len, tx_info.signature);

    return (
        version=tx_info.version,
        account_contract_address=tx_info.account_contract_address,
        max_fee=tx_info.max_fee,
        signature_len=tx_info.signature_len,
        signature_hash=signature_sum,
        transaction_hash=tx_info.transaction_hash,
        chain_id=tx_info.chain_id,
    );
}
