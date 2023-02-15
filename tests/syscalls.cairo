%lang starknet

from starkware.cairo.common.alloc import alloc
from starkware.starknet.common.syscalls import get_block_number, emit_event

@external
func test_get_block_number{syscall_ptr: felt*}() -> (block_number: felt) {
    let block_number = get_block_number();

    return (block_number);
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

@event
func test_event(a: felt, b: felt, c: felt) {
}
