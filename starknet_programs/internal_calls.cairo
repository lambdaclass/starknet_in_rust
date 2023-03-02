%lang starknet

@contract_interface
namespace ISelf {
    func a() {
    }

    func b() {
    }

    func c() {
    }
}

@external
func a{syscall_ptr: felt*, range_check_ptr}() {
    ISelf.library_call_b(
        class_hash=0x0101010101010101010101010101010101010101010101010101010101010101
    );
    return ();
}

@external
func b{syscall_ptr: felt*, range_check_ptr}() {
    ISelf.library_call_c(
        class_hash=0x0101010101010101010101010101010101010101010101010101010101010101
    );
    return ();
}

@external
func c{syscall_ptr: felt*, range_check_ptr}() {
    return ();
}
