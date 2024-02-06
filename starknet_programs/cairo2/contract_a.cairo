#[starknet::interface]
trait IContractA<TContractState> {
   fn foo(ref self: TContractState, a: u128) -> u128;
}

#[starknet::contract]
mod ContractA {
    use traits::Into;
    use starknet::info::get_contract_address;

    #[storage]
    struct Storage {
        value: u128, 
    }

    #[constructor]
    fn constructor(ref self: ContractState, value_: u128) {
        self.value.write(value_);
    }

    #[external(v0)]
    impl ContractA of super::IContractA<ContractState> {
        fn foo(ref self: ContractState, a: u128) -> u128 {
            let value = self.value.read();
            self.value.write(a);
            value
        }
    }
}
