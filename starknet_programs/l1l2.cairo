// Contract taken from:
// https://www.cairo-lang.org/docs/_static/l1l2.cairo

%lang starknet

from starkware.cairo.common.alloc import alloc
from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.cairo.common.math import assert_nn
from starkware.starknet.common.messages import send_message_to_l1

const L1_CONTRACT_ADDRESS = (0x8359E4B0152ed5A731162D3c7B0D8D56edB165A0);
const MESSAGE_WITHDRAW = 0;

// A mapping from a user (L1 Ethereum address) to their balance.
@storage_var
func balance(user: felt) -> (res: felt) {
}

@view
func get_balance{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(user: felt) -> (
    balance: felt
) {
    let (res) = balance.read(user=user);
    return (balance=res);
}

@external
func increase_balance{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    user: felt, amount: felt
) {
    let (res) = balance.read(user=user);
    balance.write(user, res + amount);
    return ();
}

@external
func withdraw{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    user: felt, amount: felt
) {
    // Make sure 'amount' is positive.
    assert_nn(amount);

    let (res) = balance.read(user=user);
    tempvar new_balance = res - amount;

    // Make sure the new balance will be positive.
    assert_nn(new_balance);

    // Update the new balance.
    balance.write(user, new_balance);

    // Send the withdrawal message.
    let (message_payload: felt*) = alloc();
    assert message_payload[0] = MESSAGE_WITHDRAW;
    assert message_payload[1] = user;
    assert message_payload[2] = amount;
    send_message_to_l1(to_address=L1_CONTRACT_ADDRESS, payload_size=3, payload=message_payload);

    return ();
}

@l1_handler
func deposit{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    from_address: felt, user: felt, amount: felt
) {
    // Make sure the message was sent by the intended L1 contract.
    assert from_address = L1_CONTRACT_ADDRESS;

    // Read the current balance.
    let (res) = balance.read(user=user);

    // Compute and update the new balance.
    tempvar new_balance = res + amount;
    balance.write(user, new_balance);

    return ();
}
