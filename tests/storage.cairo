%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin

@storage_var
func _counter() -> (res: felt) {
}

@external
func write_and_read{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (res:felt) {
     _counter.write(42);
     return _counter.read();
}
