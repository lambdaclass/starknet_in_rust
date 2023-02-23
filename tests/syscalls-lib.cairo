%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin
from starkware.starknet.common.syscalls import get_contract_address

@storage_var
func lib_state() -> (res: felt) {
}

@l1_handler
func on_event{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr: felt}(
    from_address: felt
) {
    lib_state.write(from_address);

    return ();
}

@external
func stateless_func{syscall_ptr: felt*}(a: felt, b: felt) -> (answer: felt) {
    let answer = a * b;
    return (answer=answer);
}

@external
func stateful_func{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr: felt}() {
    let (value) = lib_state.read();
    lib_state.write(value + 1);

    return ();
}

@external
func stateful_get_contract_address{syscall_ptr: felt*}() -> (contract_address: felt) {
    let contract_address = get_contract_address();

    return (contract_address);
}
