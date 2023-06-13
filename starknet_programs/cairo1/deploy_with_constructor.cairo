#[contract]
mod DeployTest {
    use core::result::ResultTrait;
    use starknet::syscalls::deploy_syscall;
    use starknet::class_hash::ClassHash;
    use starknet::contract_address::ContractAddress;
    use starknet::class_hash::Felt252TryIntoClassHash;
    use option::OptionTrait;
    use traits::TryInto;
    use array::ArrayTrait;

    #[external]
    fn deploy_test(class_hash: felt252, contract_address_salt: felt252, address: felt252, value: felt252) -> ContractAddress {
        let mut calldata = ArrayTrait::new();
        calldata.append(address);
        calldata.append(value);
        let (address0, _) = deploy_syscall(class_hash.try_into().unwrap(), contract_address_salt, calldata.span(), false).unwrap();
        address0
    }
}
