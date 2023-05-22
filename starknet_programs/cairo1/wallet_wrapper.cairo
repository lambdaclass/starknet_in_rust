#[abi]
trait SimpleWallet {
    #[constructor]
    fn constructor(initial_balance: felt252);

    #[view]
    fn get_balance() -> felt252;

    #[external]
    fn increase_balance(amount: felt252);
}

#[contract]
mod WalletWrapper {
    use super::SimpleWalletDispatcherTrait; 
    use super::SimpleWalletDispatcher;
    use starknet::ContractAddress;


    #[constructor]
    fn constructor(initial_balance: felt252, simple_wallet_contract_address: ContractAddress) {
        SimpleWalletDispatcher {contract_address: simple_wallet_contract_address}.constructor(initial_balance)
    }

    #[view]
    fn get_balance(simple_wallet_contract_address: ContractAddress) -> felt252 {
        SimpleWalletDispatcher {contract_address: simple_wallet_contract_address}.get_balance()
    }

    #[external]
    fn increase_balance(amount: felt252, simple_wallet_contract_address: ContractAddress) {
        SimpleWalletDispatcher {contract_address: simple_wallet_contract_address}.increase_balance(amount)
    }
}
