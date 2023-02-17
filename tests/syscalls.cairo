%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.starknet.common.syscalls import (
    get_block_number,
    get_block_timestamp,
    get_caller_address,
    get_contract_address,
    get_sequencer_address,
    get_tx_info,
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

@external
func test_library_call{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr: felt}() {
    let (answer) = ISyscallsLib.library_call_stateless_func(
        class_hash=0x0202020202020202020202020202020202020202020202020202020202020202, a=21, b=2
    );
    // assert answer = 42;

    // lib_state.write(10);
    // ISyscallsLib.library_call_stateful_func(
    //     class_hash=0x0202020202020202020202020202020202020202020202020202020202020202
    // );
    // let (value) = lib_state.read();
    // assert value = 11;

    // let self_contact_address = get_contract_address();
    // let call_contact_address = ISyscallsLib.library_call_stateful_get_contract_address(
    //     class_hash=0x0202020202020202020202020202020202020202020202020202020202020202
    // );
    // assert self_contact_address = call_contact_address;

    return ();
}
