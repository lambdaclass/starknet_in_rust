%lang starknet

from starkware.cairo.common.alloc import alloc
from starkware.starknet.common.messages import send_message_to_l1
from starkware.starknet.common.syscalls import (
    emit_event,
    get_block_number,
    get_block_timestamp,
    get_caller_address,
    get_contract_address,
    get_sequencer_address,
    get_tx_info,
    get_tx_signature,
)

@event
func test_event(a: felt, b: felt, c: felt) {
}

func array_sum(len: felt, arr: felt*) -> felt {
    if (len == 0) {
        return 0;
    }

    let sum_of_rest = array_sum(len - 1, arr + 1);
    return arr[0] + sum_of_rest;
}

@external
func test_emit_event{syscall_ptr: felt*, range_check_ptr: felt}() {
    test_event.emit(1, 2, 3);
    test_event.emit(2, 4, 6);
    test_event.emit(1234, 5678, 9012);

    let (keys) = alloc();
    // keys[0] = sn_keccak("test_event");
    assert keys[0] = 1411988894588762257996488304248816144105085324254724450756588685947827422338;
    let (data) = alloc();
    assert data[0] = 2468;
    emit_event(1, keys, 1, data);

    return ();
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
func test_get_tx_signature{syscall_ptr: felt*}() -> (signature_len: felt, signature_hash: felt) {
    alloc_locals;

    let (local signature_len, local signature) = get_tx_signature();
    let signature_sum = array_sum(signature_len, signature);

    return (signature_len, signature_sum);
}

@external
func test_send_message_to_l1{syscall_ptr: felt*}() {
    let (payload) = alloc();
    assert payload[0] = 1;
    assert payload[1] = 2;
    assert payload[2] = 3;
    send_message_to_l1(1111, 3, payload);

    let (payload) = alloc();
    assert payload[0] = 2;
    assert payload[1] = 4;
    send_message_to_l1(1111, 2, payload);

    let (payload) = alloc();
    assert payload[0] = 3;
    send_message_to_l1(1111, 1, payload);

    return ();
}
