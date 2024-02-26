#[starknet::interface]
trait IContractTrait<TContractState> {
    fn return_42(ref self: TContractState) -> felt252;
    fn return_44(ref self: TContractState) -> felt252;
}

#[starknet::contract]
mod Callee {
    #[storage]
    struct Storage {
        balance: felt252,
    }

    #[constructor]
    fn constructor(ref self: ContractState, initial_balance: felt252) {
        self.balance.write(initial_balance);
    }

    #[abi(embed_v0)]
    impl IContractTrait of super::IContractTrait<ContractState> {
        fn return_42(ref self: ContractState) -> felt252 {
            42
        }

        fn return_44(ref self: ContractState) -> felt252 {
            44
        }
    }
}
