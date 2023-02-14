%lang starknet

from starkware.starknet.common.syscalls import get_block_number, get_sequencer_address

@external
func test_get_block_number{syscall_ptr: felt*}() -> (block_number: felt) {
    let block_number = get_block_number();

    return (block_number);
}

@external
func test_get_sequencer_address{syscall_ptr: felt*}() -> (sequencer_address: felt) {
    let sequencer_address = get_sequencer_address();

    return (sequencer_address);
}
