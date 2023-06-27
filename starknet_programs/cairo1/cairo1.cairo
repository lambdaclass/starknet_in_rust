#[abi]
trait IOtherContract {
    fn decrease_allowed() -> bool;
}

#[contract]
mod CounterContract {
    use starknet::ContractAddress;
    use super::{
        IOtherContractDispatcher, 
        IOtherContractDispatcherTrait, 
        IOtherContractLibraryDispatcher
    };

    struct Storage {
        counter: u128,
        other_contract: IOtherContractDispatcher
    }

    #[event]
    fn counter_increased(amount: u128) {}
    #[event]
    fn counter_decreased(amount: u128) {}

    #[constructor]
    fn constructor(initial_counter: u128, other_contract_addr: ContractAddress) {
        counter::write(initial_counter);
        other_contract::write(IOtherContractDispatcher { contract_address: other_contract_addr });
    }

    #[external]
    fn increase_counter(amount: u128) {
        let current = counter::read();
        counter::write(current + amount);
        counter_increased(amount);
    }

    #[external]
    fn decrease_counter(amount: u128) {
        let allowed = other_contract::read().decrease_allowed();
        if allowed {
           let current = counter::read();
           counter::write(current - amount);
           counter_decreased(amount);
        }
    }

   #[view]
   fn get_counter() -> u128 {
      counter::read()
   }
}