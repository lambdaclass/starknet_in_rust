%lang starknet

from starkware.starknet.common.syscalls import get_block_number, get_caller_address

@external
func test_get_block_number{syscall_ptr: felt*}() -> (block_number: felt) {
    let block_number = get_block_number();

    return (block_number);
}

@external
func test_get_caller_address{syscall_ptr: felt*}() -> (caller_address: felt) {
    let caller_address = get_caller_address();

    return (caller_address);
}
