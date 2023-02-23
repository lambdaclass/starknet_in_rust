%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin

@storage_var
func constant() -> (res: felt) {
}

@constructor
func constructor{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(
    _constant: felt
) {
    constant.write(_constant);
    return ();
}

@external
func get_constant{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr} () -> (res: felt) {
    return constant.read();
    }

@external
func sum_constant{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr} (n) -> (res: felt) {
    let (c) = constant.read();
    return (c + n,);
}

@external
func mult_constant{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr} (n) -> (res: felt) {
    let (c) = constant.read();
    return (c * n,);
}
