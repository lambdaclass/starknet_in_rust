#[starknet::interface]
trait ISendMessageToL1<TContractState> {
    fn send_msg(ref self: TContractState);
}

#[starknet::contract]
mod SendMessageToL1 {

    use starknet::syscalls::send_message_to_l1_syscall;
    use array::{Array, ArrayTrait};

    #[storage]
    struct Storage{
    }

    #[external(v0)]
    impl SendMessageToL1 of super::ISendMessageToL1<ContractState> {
        fn send_msg(ref self: ContractState) {
            let mut payload = array::array_new::<felt252>();
            payload.append(555);
            payload.append(666);
            send_message_to_l1_syscall(444, payload.span());
        }
    }
}
