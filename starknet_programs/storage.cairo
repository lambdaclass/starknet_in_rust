%lang starknet
from starkware.cairo.common.cairo_builtins import HashBuiltin

struct SomeStruct {
    some_felt: felt,
    another_felt: felt,
}

@storage_var
func _counter() -> (res: felt) {
}

@storage_var
func _struct(id: felt) -> (res: SomeStruct) {
}


@external
func write_and_read{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}() -> (res:felt) {
     _counter.write(42);
     return _counter.read();
}

@external
func write_at{syscall_ptr: felt*, pedersen_ptr: HashBuiltin*, range_check_ptr}(id: felt, some_felt: felt, another_felt: felt) {
    tempvar some_struct: SomeStruct = SomeStruct(some_felt=some_felt, another_felt=another_felt);
    _struct.write(id=id, value=some_struct);
    return ();
}
