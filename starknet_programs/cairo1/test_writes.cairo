#[contract]
mod Write {
    use starknet::get_contract_address;
    use starknet::call_contract_syscall;
    use starknet::storage_access::StorageAddress;
    use array::ArrayTrait;

    struct Storage {
        foo: felt252
    }

    #[external]
    fn write_foo(val: felt252, address: StorageAddress) -> felt252 {
        starknet::syscalls::storage_write_syscall(0, address, val).unwrap_syscall();
        val
    }

    #[external]
    fn call_other(function_selector: felt252, val: felt252, address: felt252) {
        let mut calldata = ArrayTrait::new();
        calldata.append(val);
        calldata.append(address);
        call_contract_syscall(get_contract_address(), function_selector, calldata.span()).unwrap_syscall();
    }

    #[view]
    fn get_foo() -> felt252 {
        foo::read()
    }
}
