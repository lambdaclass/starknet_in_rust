%lang starknet

from starkware.cairo.common.alloc import alloc
from starkware.starknet.common.messages import send_message_to_l1
from starkware.starknet.common.syscalls import get_block_number

@external
func test_get_block_number{syscall_ptr: felt*}() -> (block_number: felt) {
    let block_number = get_block_number();

    return (block_number);
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
