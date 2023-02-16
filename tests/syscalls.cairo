%lang starknet

from starkware.starknet.common.syscalls import (
    get_block_number,
    get_block_timestamp,
    get_caller_address,
    get_contract_address,
    get_sequencer_address,
)

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
func test_get_caller_address{syscall_ptr: felt*}() -> (caller_address: felt) {
    let caller_address = get_caller_address();

    return (caller_address);
}

@external
func test_get_contract_address{syscall_ptr: felt*}() -> (contract_address: felt) {
    let contract_address = get_contract_address();

    return (contract_address);
}

@external
func test_get_sequencer_address{syscall_ptr: felt*}() -> (sequencer_address: felt) {
    let sequencer_address = get_sequencer_address();

    return (sequencer_address);
}
