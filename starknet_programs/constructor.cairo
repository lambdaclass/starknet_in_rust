%lang starknet

from starkware.cairo.common.cairo_builtins import HashBuiltin

// Define a storage variable for the owner address.
@storage_var
func owner() -> (owner_address: felt) {
}

@constructor
func constructor{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr,
}(owner_address: felt) {
    owner.write(value=owner_address);
    return ();
}

@view
func get_owner{
    syscall_ptr: felt*,
    pedersen_ptr: HashBuiltin*,
    range_check_ptr,
}() -> (address: felt) {
    let (address) = owner.read();
    return (address=address);
}
