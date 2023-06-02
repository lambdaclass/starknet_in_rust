%lang starknet
from starkware.starknet.common.syscalls import replace_class

@view
func get_number() -> (number: felt) {
    return (number=33);
}

@external
func upgrade{syscall_ptr: felt*}(new_class_hash: felt) {
    replace_class(class_hash=new_class_hash);
    return();
}
