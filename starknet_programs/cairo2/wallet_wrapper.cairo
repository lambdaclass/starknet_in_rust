#[starknet::interface]
trait SimpleWallet<TContractState> {
    fn get_balance(self: @TContractState) -> felt252;
    fn increase_balance(ref self: TContractState, amount: felt252);
}

#[starknet::interface]
trait IWalletWrapper<TContractState> {
    fn get_balance(self: @TContractState, simple_wallet_contract_address: starknet::ContractAddress) -> felt252;
    fn increase_balance(ref self: TContractState, amount: felt252, simple_wallet_contract_address: starknet::ContractAddress); 
}

#[starknet::contract]
mod WalletWrapper {
    use super::SimpleWalletDispatcherTrait; 
    use super::SimpleWalletDispatcher;
    use starknet::ContractAddress;

    #[storage]
    struct Storage{
    }

    #[external(v0)]
    impl WalletWrapper of super::IWalletWrapper<ContractState> {
        fn get_balance(self: @ContractState, simple_wallet_contract_address: ContractAddress) -> felt252 {
            SimpleWalletDispatcher {contract_address: simple_wallet_contract_address}.get_balance()
        }
        fn increase_balance(ref self: ContractState, amount: felt252, simple_wallet_contract_address: ContractAddress) {
            SimpleWalletDispatcher {contract_address: simple_wallet_contract_address}.increase_balance(amount)
        }
    }
}
