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

    #[external(v0)]
    fn return_42(ref self: ContractState) -> felt252 {
        42
    }

    #[external(v0)]
    fn return_44(ref self: ContractState) -> felt252 {
        44
    }
}