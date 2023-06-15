#[abi]
trait SendMessageToL1 {

    #[external]
    fn send_simple_message_to_l1(to_address: felt252, message: felt252);

}

#[contract]
mod SendMessages {
    use super::SendMessageToL1DispatcherTrait; 
    use super::SendMessageToL1Dispatcher;
    use starknet::ContractAddress;
    use starknet::contract_address_try_from_felt252;
    use option::OptionTrait;

    const SEND_MESSAGES_CONTRACT_ADDRESS: felt252 = 1;  //Hardcoded value in test

    #[external]
    fn send_sequential_messages(to_address: felt252, message1: felt252, message2: felt252) {
        let address = contract_address_try_from_felt252(SEND_MESSAGES_CONTRACT_ADDRESS).unwrap();
        SendMessageToL1Dispatcher {contract_address: address}.send_simple_message_to_l1(to_address, message1);
        SendMessageToL1Dispatcher {contract_address: address}.send_simple_message_to_l1(to_address, message2);
    }
}