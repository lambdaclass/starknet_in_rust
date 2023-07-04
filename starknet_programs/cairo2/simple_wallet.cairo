#[starknet::interface]
trait ISimpleWallet<TContractState> {
    fn get_balance(ref self: TContractState) -> felt252;
    fn increase_balance(ref self: TContractState, amount: felt252);
}

#[starknet::contract]
mod SimpleWallet {

    #[storage]
    struct Storage {
        balance: felt252,
    }

    #[constructor]
    fn constructor(ref self: ContractState, initial_balance: felt252) {
        self.balance.write(initial_balance);
    }

    #[external(v0)]
   impl SimpleWallet of super::ISimpleWallet<ContractState> {
        fn get_balance(ref self: ContractState) -> felt252 {
            self.balance.read()
        }

        fn increase_balance(ref self: ContractState, amount: felt252) {
            let current_balance = self.balance.read();
            self.balance.write(current_balance + amount)
        }
    }    
}
