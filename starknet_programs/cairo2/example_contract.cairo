#[starknet::interface]
trait IExampleContract<TContractState> {
   fn get_balance(ref self: TContractState) -> u128;
   fn increase_balance(ref self: TContractState, amount: u128);
}

#[starknet::contract]
mod ExampleContract {
    use traits::Into;
    use starknet::info::get_contract_address;

    #[storage]
    struct Storage {
        balance: u128,
    }

    #[constructor]
    fn constructor(ref self: ContractState) {
    }

    #[abi(embed_v0)]
    impl ExampleContract of super::IExampleContract<ContractState> {
        fn get_balance(ref self: ContractState) -> u128 {
            self.balance.read()
        }

        fn increase_balance(ref self: ContractState, amount: u128) {
            let balance = self.balance.read();
            self.balance.write(balance + amount);
        }
    }
}
