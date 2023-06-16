%lang starknet

from starkware.starknet.common.messages import send_message_to_l1
from starkware.cairo.common.alloc import alloc


@external
func send_simple_message_to_l1{
syscall_ptr: felt*,
}(to_address: felt, message: felt) {
    let payload: felt* = alloc();
    assert payload[0] = message; 
    send_message_to_l1(to_address, 1, payload);
    return ();
}
