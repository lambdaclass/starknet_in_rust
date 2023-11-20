#[abi]
trait SimpleWallet {
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

    #[view]
    fn get_balance(simple_wallet_contract_address: ContractAddress) -> felt252 {
        SimpleWalletDispatcher {contract_address: simple_wallet_contract_address}.get_balance()
    }

    #[external]
    fn increase_balance(amount: felt252, simple_wallet_contract_address: ContractAddress) {
        SimpleWalletDispatcher {contract_address: simple_wallet_contract_address}.increase_balance(amount)
    }

    #[external]
    fn increase_balance_recursive(amount: felt252, simple_wallet_contract_address: ContractAddress) {
        if amount == 0 {
            return();
        }
        SimpleWalletDispatcher {contract_address: simple_wallet_contract_address}.increase_balance(1);
        increase_balance_recursive(amount - 1, simple_wallet_contract_address)
    }
}
