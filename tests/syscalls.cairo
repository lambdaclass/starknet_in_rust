%lang starknet

from starkware.starknet.common.syscalls import get_block_number, get_tx_signature

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
func test_get_tx_signature{syscall_ptr: felt*}() -> (signature_len: felt, signature_hash: felt) {
    alloc_locals;

    let (local signature_len, local signature) = get_tx_signature();
    let signature_sum = array_sum(signature_len, signature);

    return (signature_len, signature_sum);
}
