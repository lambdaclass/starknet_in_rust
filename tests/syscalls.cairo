%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.starknet.common.syscalls import (
    get_block_number,
    get_block_timestamp,
    get_contract_address,
)

@storage_var
func lib_state() -> (res: felt) {
}

@contract_interface
namespace ISyscallsLib {
    func stateless_func(a: felt, b: felt) -> (answer: felt) {
    }

    func stateful_func() {
    }

    func stateful_get_contract_address() -> (contract_address: felt) {
    }
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
func library_call{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr: felt}() {
    let (answer) = ISyscallsLib.library_call_stateless_func(
        class_hash=0x0101010101010101010101010101010101010101010101010101010101010101, a=21, b=2
    );
    assert answer = 42;

    lib_state.write(10);
    ISyscallsLib.library_call_stateful_func(
        class_hash=0x0101010101010101010101010101010101010101010101010101010101010101
    );
    let (value) = lib_state.read();
    assert value = 11;

    let self_contact_address = get_contract_address();
    let call_contact_address = ISyscallsLib.library_call_stateful_get_contract_address(
        class_hash=0x0101010101010101010101010101010101010101010101010101010101010101
    );
    assert self_contact_address = call_contact_address;

    return ();
}
