#[starknet::interface]
trait ISendMessageToL1<TContractState> {
    fn send_simple_message_to_l1(self: @TContractState, to_address: felt252, message: felt252);
}

#[starknet::contract]
mod SendMessageToL1 {
    use starknet::syscalls::send_message_to_l1_syscall;
    use array::{Array, ArrayTrait};

    #[storage]
    struct Storage {
    }
    
    #[external(v0)]
    impl SendMessageToL1 of super::ISendMessageToL1<ContractState> {
        fn send_simple_message_to_l1(self: @ContractState, to_address: felt252, message: felt252) {
            let mut payload = array::array_new::<felt252>();
            payload.append(message);
            send_message_to_l1_syscall(to_address, payload.span());
        }
    }
}
