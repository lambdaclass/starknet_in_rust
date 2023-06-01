#[contract]
mod SendMessageToL1 {

    use starknet::syscalls::send_message_to_l1_syscall;
    use array::{Array, ArrayTrait};

    #[external]
    fn send_msg() {
        let mut payload = array::array_new::<felt252>();
        payload.append(555);
        payload.append(666);
        send_message_to_l1_syscall(444, payload.span());
    }
}
