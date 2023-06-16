#[contract]
mod SendMessageToL1 {
    use starknet::syscalls::send_message_to_l1_syscall;
    use array::{Array, ArrayTrait};

    #[external]
    fn send_simple_message_to_l1(to_address: felt252, message: felt252) {
        let mut payload = array::array_new::<felt252>();
        payload.append(message);
        send_message_to_l1_syscall(to_address, payload.span());
    }
}
