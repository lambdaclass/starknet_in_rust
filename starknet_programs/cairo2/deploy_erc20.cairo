use starknet::contract_address::ContractAddress;
#[starknet::interface]
trait IDeployTest<TContractState> {
    fn deploy_test(self: @TContractState, class_hash: felt252, contract_address_salt: felt252, name_: felt252, symbol_: felt252, decimals: felt252, initial_supply: felt252, recipient: felt252) -> ContractAddress;
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
        fn deploy_test(self: @ContractState, class_hash: felt252, contract_address_salt: felt252, name_: felt252, symbol_: felt252, decimals: felt252, initial_supply: felt252, recipient: felt252) -> ContractAddress {
            let mut calldata = ArrayTrait::new();
            calldata.append(name_);
            calldata.append(symbol_);
            calldata.append(decimals);
            calldata.append(initial_supply);
            calldata.append(recipient);
            assert(calldata.len() == 5, 'Wrong calldata length');
            let (address0, _) = deploy_syscall(class_hash.try_into().unwrap(), contract_address_salt, calldata.span(), false).unwrap();
            address0
        }
    }
}
