use super::{starknet_state_error::StarknetStateError, type_utils::ExecutionInfo};
use crate::{
    business_logic::{
        execution::{
            execution_entry_point::ExecutionEntryPoint,
            objects::{CallInfo, Event, TransactionExecutionContext, TransactionExecutionInfo},
        },
        fact_state::{
            in_memory_state_reader::InMemoryStateReader, state::ExecutionResourcesManager,
        },
        state::{
            cached_state::CachedState,
            state_api::{State, StateReader},
        },
        transaction::{
            error::TransactionError,
            objects::{
                internal_declare::InternalDeclare, internal_deploy::InternalDeploy,
                internal_invoke_function::InternalInvokeFunction,
            },
            transactions::Transaction,
        },
    },
    definitions::{constants::TRANSACTION_VERSION, general_config::StarknetGeneralConfig},
    services::api::{
        contract_classes::deprecated_contract_class::{ContractClass, EntryPointType},
        messages::StarknetMessageToL1,
    },
    utils::{Address, ClassHash},
};
use cairo_vm::felt::Felt252;
use num_traits::{One, Zero};
use std::collections::HashMap;

// ---------------------------------------------------------------------
/// StarkNet testing object. Represents a state of a StarkNet network.
pub struct StarknetState {
    pub state: CachedState<InMemoryStateReader>,
    pub(crate) general_config: StarknetGeneralConfig,
    l2_to_l1_messages: HashMap<Vec<u8>, usize>,
    l2_to_l1_messages_log: Vec<StarknetMessageToL1>,
    events: Vec<Event>,
}

impl StarknetState {
    pub fn new(config: Option<StarknetGeneralConfig>) -> Self {
        let general_config = config.unwrap_or_default();
        let state_reader = InMemoryStateReader::default();

        let state = CachedState::new(state_reader, Some(HashMap::new()), Some(HashMap::new()));

        let l2_to_l1_messages = HashMap::new();
        let l2_to_l1_messages_log = Vec::new();

        let events = Vec::new();
        StarknetState {
            state,
            general_config,
            l2_to_l1_messages,
            l2_to_l1_messages_log,
            events,
        }
    }

    pub fn new_with_states(
        config: Option<StarknetGeneralConfig>,
        state: CachedState<InMemoryStateReader>,
    ) -> Self {
        let general_config = config.unwrap_or_default();
        let l2_to_l1_messages = HashMap::new();
        let l2_to_l1_messages_log = Vec::new();

        let events = Vec::new();
        StarknetState {
            state,
            general_config,
            l2_to_l1_messages,
            l2_to_l1_messages_log,
            events,
        }
    }

    // ------------------------------------------------------------------------------------
    /// Declares a contract class.
    /// Returns the class hash and the execution info.
    /// Args:
    /// contract_class - a compiled StarkNet contract
    pub fn declare(
        &mut self,
        contract_class: ContractClass,
        hash_value: Option<Felt252>,
    ) -> Result<(ClassHash, TransactionExecutionInfo), TransactionError> {
        let tx = InternalDeclare::new(
            contract_class,
            self.chain_id(),
            Address(Felt252::one()),
            0,
            0,
            Vec::new(),
            0.into(),
            hash_value,
        )?;

        let tx_execution_info = tx.execute(&mut self.state, &self.general_config)?;

        Ok((tx.class_hash, tx_execution_info))
    }

    /// Invokes a contract function. Returns the execution info.

    #[allow(clippy::too_many_arguments)]
    pub fn invoke_raw(
        &mut self,
        contract_address: Address,
        selector: Felt252,
        calldata: Vec<Felt252>,
        max_fee: u128,
        signature: Option<Vec<Felt252>>,
        nonce: Option<Felt252>,
        hash_value: Option<Felt252>,
    ) -> Result<TransactionExecutionInfo, StarknetStateError> {
        let tx = self.create_invoke_function(
            contract_address,
            selector,
            calldata,
            max_fee,
            signature,
            nonce,
            hash_value,
        )?;

        let mut tx = Transaction::InvokeFunction(tx);
        self.execute_tx(&mut tx)
    }

    /// Builds the transaction execution context and executes the entry point.
    /// Returns the CallInfo.
    pub fn execute_entry_point_raw(
        &mut self,
        contract_address: Address,
        entry_point_selector: Felt252,
        calldata: Vec<Felt252>,
        caller_address: Address,
    ) -> Result<CallInfo, StarknetStateError> {
        let call = ExecutionEntryPoint::new(
            contract_address,
            calldata,
            entry_point_selector,
            caller_address,
            EntryPointType::External,
            None,
            None,
            0,
        );

        let mut resources_manager = ExecutionResourcesManager::default();

        let tx_execution_context = TransactionExecutionContext::default();
        let call_info = call.execute(
            &mut self.state,
            &self.general_config,
            &mut resources_manager,
            &tx_execution_context,
            false,
        )?;

        let exec_info = ExecutionInfo::Call(Box::new(call_info.clone()));
        self.add_messages_and_events(&exec_info)?;

        Ok(call_info)
    }

    /// Deploys a contract. Returns the contract address and the execution info.
    /// Args:
    /// contract_class - a compiled StarkNet contract
    /// contract_address_salt
    /// the salt to use for deploying. Otherwise, the salt is randomized.
    pub fn deploy(
        &mut self,
        contract_class: ContractClass,
        constructor_calldata: Vec<Felt252>,
        contract_address_salt: Address,
        hash_value: Option<Felt252>,
    ) -> Result<(Address, TransactionExecutionInfo), StarknetStateError> {
        let chain_id = self.general_config.starknet_os_config.chain_id.to_felt();
        let mut tx = Transaction::Deploy(InternalDeploy::new(
            contract_address_salt,
            contract_class.clone(),
            constructor_calldata,
            chain_id,
            TRANSACTION_VERSION,
            hash_value,
        )?);

        self.state
            .set_contract_class(&tx.contract_hash(), &contract_class)?;

        let tx_execution_info = self.execute_tx(&mut tx)?;
        Ok((tx.contract_address(), tx_execution_info))
    }

    pub fn execute_tx(
        &mut self,
        tx: &mut Transaction,
    ) -> Result<TransactionExecutionInfo, StarknetStateError> {
        let tx = tx.execute(&mut self.state, &self.general_config)?;
        let tx_execution_info = ExecutionInfo::Transaction(Box::new(tx.clone()));
        self.add_messages_and_events(&tx_execution_info)?;
        Ok(tx)
    }

    pub fn add_messages_and_events(
        &mut self,
        exec_info: &ExecutionInfo,
    ) -> Result<(), StarknetStateError> {
        for msg in exec_info.get_sorted_l2_to_l1_messages()? {
            let starknet_message =
                StarknetMessageToL1::new(msg.from_address, msg.to_address, msg.payload);

            self.l2_to_l1_messages_log.push(starknet_message.clone());
            let message_hash = starknet_message.get_hash();

            if self.l2_to_l1_messages.contains_key(&message_hash) {
                let val = self.l2_to_l1_messages.get(&message_hash).unwrap();
                self.l2_to_l1_messages.insert(message_hash, val + 1);
            } else {
                self.l2_to_l1_messages.insert(message_hash, 1);
            }
        }

        let mut events = exec_info.get_sorted_events()?;
        self.events.append(&mut events);
        Ok(())
    }

    /// Consumes the given message hash.
    pub fn consume_message_hash(
        &mut self,
        message_hash: Vec<u8>,
    ) -> Result<(), StarknetStateError> {
        let val = self
            .l2_to_l1_messages
            .get(&message_hash)
            .ok_or(StarknetStateError::InvalidMessageHash)?;

        if val.is_zero() {
            Err(StarknetStateError::InvalidMessageHash)
        } else {
            self.l2_to_l1_messages.insert(message_hash, val - 1);
            Ok(())
        }
    }

    // ------------------------
    //    Private functions
    // ------------------------

    fn chain_id(&self) -> Felt252 {
        self.general_config.starknet_os_config.chain_id.to_felt()
    }

    #[allow(clippy::too_many_arguments)]
    fn create_invoke_function(
        &mut self,
        contract_address: Address,
        entry_point_selector: Felt252,
        calldata: Vec<Felt252>,
        max_fee: u128,
        signature: Option<Vec<Felt252>>,
        nonce: Option<Felt252>,
        hash_value: Option<Felt252>,
    ) -> Result<InternalInvokeFunction, TransactionError> {
        let signature = match signature {
            Some(sign) => sign,
            None => Vec::new(),
        };

        let nonce = match nonce {
            Some(n) => n,
            None => self.state.get_nonce_at(&contract_address)?,
        };

        InternalInvokeFunction::new(
            contract_address,
            entry_point_selector,
            max_fee,
            TRANSACTION_VERSION,
            calldata,
            signature,
            self.chain_id(),
            Some(nonce),
            hash_value,
        )
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use cairo_vm::felt::felt_str;
    use num_traits::Num;

    use super::*;
    use crate::{
        business_logic::{
            execution::objects::{CallType, OrderedL2ToL1Message},
            state::state_cache::StorageEntry,
        },
        core::{
            contract_address::starknet_contract_address::compute_deprecated_class_hash,
            errors::state_errors::StateError,
        },
        definitions::{
            constants::CONSTRUCTOR_ENTRY_POINT_SELECTOR, transaction_type::TransactionType,
        },
        utils::{calculate_sn_keccak, felt_to_hash},
    };

    #[test]
    fn test_deploy() {
        let mut starknet_state = StarknetState::new(None);
        let path = PathBuf::from("starknet_programs/fibonacci.json");
        let contract_class = ContractClass::try_from(path).unwrap();
        let contract_address_salt = Address(1.into());

        // expected results

        // ----- calculate fib class hash ---------
        let hash = compute_deprecated_class_hash(&contract_class).unwrap();
        let class_hash = felt_to_hash(&hash);

        let address = Address(felt_str!(
            "2066790681318687707025847340457605657642478884993868155391041767964612021885"
        ));

        let mut actual_resources = HashMap::new();
        actual_resources.insert("l1_gas_usage".to_string(), 1224);

        let transaction_exec_info = TransactionExecutionInfo {
            validate_info: None,
            call_info: Some(CallInfo {
                caller_address: Address(0.into()),
                call_type: Some(CallType::Call),
                contract_address: address.clone(),
                code_address: None,
                class_hash: Some(class_hash),
                entry_point_selector: Some(CONSTRUCTOR_ENTRY_POINT_SELECTOR.clone()),
                entry_point_type: Some(EntryPointType::Constructor),
                ..Default::default()
            }),
            fee_transfer_info: None,
            actual_fee: 0,
            actual_resources,
            tx_type: Some(TransactionType::Deploy),
        };

        // check result is correct
        let exec = (address, transaction_exec_info);
        assert_eq!(
            starknet_state
                .deploy(contract_class.clone(), vec![], contract_address_salt, None)
                .unwrap(),
            exec
        );

        // check that properly stored contract class
        assert_eq!(
            starknet_state
                .state
                .contract_classes
                .unwrap()
                .get(&class_hash)
                .unwrap()
                .to_owned(),
            contract_class
        );
    }

    #[test]
    fn test_declare() {
        let path = PathBuf::from("starknet_programs/account_without_validation.json");
        let contract_class = ContractClass::try_from(path).unwrap();

        // Instantiate CachedState
        let mut contract_class_cache = HashMap::new();

        //  ------------ contract data --------------------
        // hack store account contract
        let hash = compute_deprecated_class_hash(&contract_class).unwrap();
        let class_hash = felt_to_hash(&hash);
        contract_class_cache.insert(class_hash, contract_class.clone());

        // store sender_address
        let sender_address = Address(1.into());
        // this is not conceptually correct as the sender address would be an
        // Account contract (not the contract that we are currently declaring)
        // but for testing reasons its ok
        let nonce = Felt252::zero();
        let storage_entry: StorageEntry = (sender_address.clone(), [19; 32]);
        let storage = Felt252::zero();

        let mut state_reader = InMemoryStateReader::default();
        state_reader
            .address_to_class_hash_mut()
            .insert(sender_address.clone(), class_hash);
        state_reader
            .address_to_nonce_mut()
            .insert(sender_address.clone(), nonce.clone());
        state_reader
            .address_to_storage_mut()
            .insert(storage_entry.clone(), storage.clone());
        state_reader
            .class_hash_to_contract_class_mut()
            .insert(class_hash, contract_class.clone());

        let state = CachedState::new(state_reader, Some(contract_class_cache), None);

        //* --------------------------------------------
        //*    Create starknet state with previous data
        //* --------------------------------------------

        let mut starknet_state = StarknetState::new(None);

        starknet_state.state = state;
        starknet_state
            .state
            .state_reader
            .address_to_class_hash_mut()
            .insert(sender_address.clone(), class_hash);

        starknet_state
            .state
            .state_reader
            .address_to_nonce_mut()
            .insert(sender_address.clone(), nonce);
        starknet_state
            .state
            .state_reader
            .address_to_storage_mut()
            .insert(storage_entry, storage);
        starknet_state
            .state
            .state_reader
            .class_hash_to_contract_class_mut()
            .insert(class_hash, contract_class);

        // --------------------------------------------
        //      Test declare with starknet state
        // --------------------------------------------
        let fib_path = PathBuf::from("starknet_programs/fibonacci.json");
        let fib_contract_class = ContractClass::try_from(fib_path).unwrap();

        let (ret_class_hash, _exec_info) = starknet_state
            .declare(fib_contract_class.clone(), None)
            .unwrap();

        //* ---------------------------------------
        //              Expected result
        //* ---------------------------------------

        // ----- calculate fib class hash ---------
        let hash = compute_deprecated_class_hash(&fib_contract_class).unwrap();
        let fib_class_hash = felt_to_hash(&hash);

        // check that it return the correct clash hash
        assert_eq!(ret_class_hash, fib_class_hash);

        // check that state has store has store accounts class hash
        assert_eq!(
            starknet_state
                .state
                .get_class_hash_at(&sender_address)
                .unwrap()
                .to_owned(),
            class_hash
        );
        // check that state has store fib class hash
        assert_eq!(
            starknet_state
                .state
                .get_contract_class(&fib_class_hash)
                .unwrap(),
            fib_contract_class
        );
    }

    #[test]
    fn test_invoke() {
        // 1) deploy fibonacci
        // 2) invoke call over fibonacci

        let mut starknet_state = StarknetState::new(None);
        let path = PathBuf::from("starknet_programs/fibonacci.json");
        let contract_class = ContractClass::try_from(path).unwrap();
        let calldata = [1.into(), 1.into(), 10.into()].to_vec();
        let contract_address_salt = Address(1.into());

        let (contract_address, _exec_info) = starknet_state
            .deploy(contract_class.clone(), vec![], contract_address_salt, None)
            .unwrap();

        // fibonacci selector
        let selector = Felt252::from_str_radix(
            "112e35f48499939272000bd72eb840e502ca4c3aefa8800992e8defb746e0c9",
            16,
        )
        .unwrap();

        // Statement **not** in blockifier.
        starknet_state
            .state
            .cache_mut()
            .nonce_initial_values_mut()
            .insert(contract_address.clone(), Felt252::zero());

        let tx_info = starknet_state
            .invoke_raw(
                contract_address,
                selector.clone(),
                calldata,
                0,
                Some(Vec::new()),
                Some(Felt252::zero()),
                None,
            )
            .unwrap();

        // expected result
        // ----- calculate fib class hash ---------
        let hash = compute_deprecated_class_hash(&contract_class).unwrap();
        let fib_class_hash = felt_to_hash(&hash);

        let address = felt_str!(
            "2066790681318687707025847340457605657642478884993868155391041767964612021885"
        );
        let actual_resources = HashMap::from([
            ("l1_gas_usage".to_string(), 0),
            ("range_check_builtin".to_string(), 70),
            ("pedersen_builtin".to_string(), 16),
        ]);

        let expected_info = TransactionExecutionInfo {
            validate_info: None,
            call_info: Some(CallInfo {
                caller_address: Address(Felt252::zero()),
                call_type: Some(CallType::Call),
                contract_address: Address(address),
                code_address: None,
                class_hash: Some(fib_class_hash),
                entry_point_selector: Some(selector),
                entry_point_type: Some(EntryPointType::External),
                calldata: vec![1.into(), 1.into(), 10.into()],
                retdata: vec![144.into()],
                ..Default::default()
            }),
            actual_resources,
            tx_type: Some(TransactionType::InvokeFunction),
            ..Default::default()
        };

        assert_eq!(tx_info, expected_info);
    }

    #[test]
    fn test_execute_entry_point_raw() {
        let mut starknet_state = StarknetState::new(None);
        let path = PathBuf::from("starknet_programs/fibonacci.json");
        let contract_class = ContractClass::try_from(path).unwrap();
        let contract_address_salt = Address(1.into());

        let (contract_address, _exec_info) = starknet_state
            .deploy(contract_class, vec![], contract_address_salt, None)
            .unwrap();

        // fibonacci selector
        let entrypoint_selector = Felt252::from_bytes_be(&calculate_sn_keccak(b"fib"));
        let result = starknet_state
            .execute_entry_point_raw(
                contract_address,
                entrypoint_selector,
                vec![1.into(), 1.into(), 10.into()],
                Address(0.into()),
            )
            .unwrap()
            .retdata;
        assert_eq!(result, vec![144.into()]);
    }

    #[test]
    fn test_add_messages_and_events() {
        let mut starknet_state = StarknetState::new(None);
        let test_msg_1 = OrderedL2ToL1Message {
            order: 0,
            to_address: Address(0.into()),
            payload: vec![0.into()],
        };
        let test_msg_2 = OrderedL2ToL1Message {
            order: 1,
            to_address: Address(0.into()),
            payload: vec![0.into()],
        };

        let exec_info = ExecutionInfo::Call(Box::new(CallInfo {
            l2_to_l1_messages: vec![test_msg_1, test_msg_2],
            ..Default::default()
        }));

        starknet_state.add_messages_and_events(&exec_info).unwrap();
        let msg_hash =
            StarknetMessageToL1::new(Address(0.into()), Address(0.into()), vec![0.into()])
                .get_hash();

        let messages = starknet_state.l2_to_l1_messages;
        let mut expected_messages = HashMap::new();
        expected_messages.insert(msg_hash, 2);
        assert_eq!(messages, expected_messages);
    }

    #[test]
    fn test_consume_message_hash() {
        let mut starknet_state = StarknetState::new(None);
        let test_msg_1 = OrderedL2ToL1Message {
            order: 0,
            to_address: Address(0.into()),
            payload: vec![0.into()],
        };
        let test_msg_2 = OrderedL2ToL1Message {
            order: 1,
            to_address: Address(0.into()),
            payload: vec![0.into()],
        };

        let exec_info = ExecutionInfo::Call(Box::new(CallInfo {
            l2_to_l1_messages: vec![test_msg_1, test_msg_2],
            ..Default::default()
        }));

        starknet_state.add_messages_and_events(&exec_info).unwrap();
        let msg_hash =
            StarknetMessageToL1::new(Address(0.into()), Address(0.into()), vec![0.into()])
                .get_hash();

        starknet_state
            .consume_message_hash(msg_hash.clone())
            .unwrap();
        let messages = starknet_state.l2_to_l1_messages;
        let mut expected_messages = HashMap::new();
        expected_messages.insert(msg_hash, 1);
        assert_eq!(messages, expected_messages);
    }

    #[test]
    fn test_consume_message_hash_twice_should_fail() {
        let mut starknet_state = StarknetState::new(None);
        let test_msg = OrderedL2ToL1Message {
            order: 0,
            to_address: Address(0.into()),
            payload: vec![0.into()],
        };

        let exec_info = ExecutionInfo::Call(Box::new(CallInfo {
            l2_to_l1_messages: vec![test_msg],
            ..Default::default()
        }));

        starknet_state.add_messages_and_events(&exec_info).unwrap();
        let msg_hash =
            StarknetMessageToL1::new(Address(0.into()), Address(0.into()), vec![0.into()])
                .get_hash();

        starknet_state
            .consume_message_hash(msg_hash.clone())
            .unwrap();
        let err = starknet_state.consume_message_hash(msg_hash).unwrap_err();
        assert_matches!(err, StarknetStateError::InvalidMessageHash);
    }

    #[test]
    fn test_create_invoke_function_should_fail_with_none_contract_state() {
        let mut starknet_state = StarknetState::new(None);

        let err = starknet_state
            .create_invoke_function(Address(0.into()), 0.into(), vec![], 0, None, None, None)
            .unwrap_err();
        assert_matches!(
            err,
            TransactionError::State(StateError::NoneContractState(_))
        );
    }
}
