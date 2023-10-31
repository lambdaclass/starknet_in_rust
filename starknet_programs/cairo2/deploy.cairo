#[starknet::interface]
trait IDeployTest<TContractState> {
    fn deploy_test(self: @TContractState, class_hash: felt252, contract_address_salt: felt252) -> starknet::contract_address::ContractAddress;
}

#[starknet::contract]
mod DeployTest {
    use core::result::ResultTrait;
    use starknet::syscalls::deploy_syscall;
    use starknet::class_hash::ClassHash;
    use starknet::contract_address::ContractAddress;
    use starknet::class_hash::Felt252TryIntoClassHash;
    use option::OptionTrait;
    use traits::TryInto;
    use array::ArrayTrait;


    #[storage]
    struct Storage {
    }

    #[external(v0)]
    impl DeployTest of super::IDeployTest<ContractState> {
        fn deploy_test(self: @ContractState, class_hash: felt252, contract_address_salt: felt252) -> ContractAddress {
            let mut calldata = ArrayTrait::new();
            calldata.append(100);
            let (address0, _) = deploy_syscall(class_hash.try_into().unwrap(), contract_address_salt, calldata.span(), false).unwrap();
            address0
        }
    }
}
