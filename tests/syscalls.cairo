%lang starknet

from starkware.starknet.common.syscalls import get_block_number

@external
func test_get_block_number{syscall_ptr: felt*}() -> (block_number: felt) {
    let block_number = get_block_number();

    return (block_number);
}
