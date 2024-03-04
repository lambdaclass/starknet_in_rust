#[starknet::interface]
trait IEcho<TContractState> {
    fn echo(ref self: TContractState, value: felt252) -> felt252;
}

#[starknet::contract]
mod Echo {
    #[storage]
    struct Storage {
        balance: felt252,
    }

    #[constructor]
    fn constructor(ref self: ContractState, initial_balance: felt252) {
        self.balance.write(initial_balance);
    }

    #[abi(embed_v0)]
    impl IEcho of super::IEcho<ContractState> {
        #[abi(per_item)]
        fn echo(ref self: ContractState, value: felt252) -> felt252 {
            value
        }
    }
}
