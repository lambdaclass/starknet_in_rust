#[contract]
mod SimpleWallet {
    struct Storage {
        balance: felt252,
    }

    #[constructor]
    fn constructor(initial_balance: felt252) {
        balance::write(initial_balance)
    }

    #[view]
    fn get_balance() -> felt252 {
        balance::read()
    }

    #[external]
    fn increase_balance(amount: felt252) {
        let current_balance = balance::read();
        balance::write(current_balance + amount)
    }
}
