#[contract]
mod ContractA {
    use traits::Into;
    use starknet::info::get_contract_address;
    struct Storage {
        value: u128, 
    }

    #[constructor]
    fn constructor(value_: u128) {
        value::write(value_);
    }

    #[external]
    fn foo(a: u128) -> u128 {
        let value = value::read();
        value::write(a);
        value
    }
}
