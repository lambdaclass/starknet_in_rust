%lang starknet

@contract_interface
namespace ISendMessageToL1 {
    func send_simple_message_to_l1(to_address: felt, message: felt) {
    }
}

const SEND_MESSAGES_CONTRACT_ADDRESS = 1; //Hardcoded value in test

@external
func send_sequential_messages{syscall_ptr: felt*, range_check_ptr: felt}(to_address: felt, message1: felt, message2) {
    ISendMessageToL1.send_simple_message_to_l1(
        contract_address=SEND_MESSAGES_CONTRACT_ADDRESS,
        to_address=to_address,
        message=message1,
    );
    ISendMessageToL1.send_simple_message_to_l1(
        contract_address=SEND_MESSAGES_CONTRACT_ADDRESS,
        to_address=to_address,
        message=message2,
    );
    return ();
}
