use super::{starknet_state_error::StarknetStateError, type_utils::ExecutionInfo};
use std::collections::HashMap;

use felt::Felt;
use num_traits::{One, Zero};

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
        contract_class::{ContractClass, EntryPointType},
        messages::StarknetMessageToL1,
    },
    utils::Address,
};

// ---------------------------------------------------------------------
/// StarkNet testing object. Represents a state of a StarkNet network.
pub(crate) struct StarknetState {
    pub(crate) state: CachedState<InMemoryStateReader>,
    pub(crate) general_config: StarknetGeneralConfig,
    l2_to_l1_messages: HashMap<Vec<u8>, usize>,
    l2_to_l1_messages_log: Vec<StarknetMessageToL1>,
    events: Vec<Event>,
}

impl StarknetState {
    #![allow(unused)] // TODO: delete once used
    pub fn new(config: Option<StarknetGeneralConfig>) -> Self {
        let general_config = config.unwrap_or_default();
        let state_reader = InMemoryStateReader::new(HashMap::new(), HashMap::new());

        let state = CachedState::new(state_reader, Some(HashMap::new()));

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
    ) -> Result<([u8; 32], TransactionExecutionInfo), TransactionError> {
        let tx = InternalDeclare::new(
            contract_class.clone(),
            self.chain_id(),
            Address(Felt::one()),
            0,
            0,
            Vec::new(),
            0.into(),
        )?;

        self.state
            .contract_classes
            .as_mut()
            .ok_or(TransactionError::MissingClassStorage)?
            .insert(tx.class_hash, contract_class);

        let mut state = self.state.apply_to_copy();
        let tx_execution_info = tx.execute(&mut state, &self.general_config)?;

        Ok((tx.class_hash, tx_execution_info))
    }

    // ----------------------------------------------------------
    /// Invokes a contract function. Returns the execution info.

    pub fn invoke_raw(
        &mut self,
        contract_address: Address,
        selector: Felt,
        calldata: Vec<Felt>,
        max_fee: u64,
        signature: Option<Vec<Felt>>,
        nonce: Option<Felt>,
    ) -> Result<TransactionExecutionInfo, TransactionError> {
        let mut tx = self.create_invoke_function(
            contract_address,
            selector,
            calldata,
            max_fee,
            signature,
            nonce,
        )?;

        let mut tx = Transaction::InvokeFunction(tx);
        self.execute_tx(&mut tx)
    }

    // -------------------------------------------------------------------------
    /// Builds the transaction execution context and executes the entry point.
    /// Returns the CallInfo.

    pub fn execute_entry_point_raw(
        &mut self,
        contract_address: Address,
        entry_point_selector: Felt,
        calldata: Vec<Felt>,
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
        );

        let mut state_copy = self.state.apply_to_copy();
        let mut resources_manager = ExecutionResourcesManager::default();

        let tx_execution_context = TransactionExecutionContext::default();
        let call_info = call.execute(
            &mut state_copy,
            &self.general_config,
            &mut resources_manager,
            &tx_execution_context,
        )?;

        let exec_info = ExecutionInfo::Call(Box::new(call_info.clone()));
        self.add_messages_and_events(&exec_info);

        Ok(call_info)
    }

    // --------------------------------------------------------------------------------------
    /// Deploys a contract. Returns the contract address and the execution info.
    /// Args:
    /// contract_class - a compiled StarkNet contract
    /// contract_address_salt
    /// the salt to use for deploying. Otherwise, the salt is randomized.

    // TODO: ask for contract_address_salt
    pub fn deploy(
        &mut self,
        contract_class: ContractClass,
        constructor_calldata: Vec<Felt>,
        contract_address_salt: Address,
    ) -> Result<(Address, TransactionExecutionInfo), StarknetStateError> {
        let chain_id = self.general_config.starknet_os_config.chain_id.to_felt();
        let mut tx = Transaction::Deploy(InternalDeploy::new(
            contract_address_salt,
            contract_class.clone(),
            constructor_calldata,
            chain_id,
            TRANSACTION_VERSION,
        )?);

        self.state
            .set_contract_class(&tx.contract_hash(), &contract_class)?;

        let tx_execution_info = self.execute_tx(&mut tx)?;
        Ok((tx.contract_address(), tx_execution_info))
    }

    pub fn execute_tx(
        &mut self,
        tx: &mut Transaction,
    ) -> Result<TransactionExecutionInfo, TransactionError> {
        let mut state_copy = self.state.apply_to_copy();
        let tx = tx.execute(&mut state_copy, &self.general_config)?;
        let tx_execution_info = ExecutionInfo::Transaction(Box::new(tx.clone()));
        self.add_messages_and_events(&tx_execution_info);
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

    fn chain_id(&self) -> Felt {
        self.general_config.starknet_os_config.chain_id.to_felt()
    }

    fn create_invoke_function(
        &mut self,
        contract_address: Address,
        entry_point_selector: Felt,
        calldata: Vec<Felt>,
        max_fee: u64,
        signature: Option<Vec<Felt>>,
        nonce: Option<Felt>,
    ) -> Result<InternalInvokeFunction, TransactionError> {
        let signature = match signature {
            Some(sign) => sign,
            None => Vec::new(),
        };

        let nonce = match nonce {
            Some(n) => n,
            None => self.state.get_nonce_at(&contract_address)?.to_owned(),
        };

        InternalInvokeFunction::new(
            contract_address,
            entry_point_selector,
            max_fee,
            calldata,
            signature,
            self.chain_id(),
            Some(nonce),
        )
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use felt::felt_str;

    use crate::{
        business_logic::{execution::objects::CallType, fact_state::contract_state::ContractState},
        core::contract_address::starknet_contract_address::compute_class_hash,
        definitions::transaction_type::TransactionType,
        utils::felt_to_hash,
    };

    use super::*;

    #[test]
    fn test_deploy() {
        let mut starknet_state = StarknetState::new(None);
        let path = PathBuf::from("starknet_programs/fibonacci.json");
        let contract_class = ContractClass::try_from(path).unwrap();
        let constructor_calldata = [1.into(), 1.into(), 10.into()].to_vec();
        let contract_address_salt = Address(1.into());

        // expected results

        // ----- calculate fib class hash ---------
        let hash = compute_class_hash(&contract_class).unwrap();
        let class_hash = felt_to_hash(&hash);

        let address = Address(felt_str!(
            "3173424428166065804253636112972198402746524727884605069568266184332607747575"
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
                entry_point_selector: None,
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
                .deploy(
                    contract_class.clone(),
                    constructor_calldata,
                    contract_address_salt
                )
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
        let hash = compute_class_hash(&contract_class).unwrap();
        let class_hash = felt_to_hash(&hash);
        contract_class_cache.insert(class_hash, contract_class);

        // store sender_address
        let sender_address = Address(1.into());
        // this is not conceptually correct as the sender address would be an
        // Account contract (not the contract that we are currently declaring)
        // but for testing reasons its ok
        let contract_state = ContractState::new(class_hash, 0.into(), HashMap::new());

        let mut state_reader = InMemoryStateReader::new(HashMap::new(), HashMap::new());
        state_reader
            .contract_states
            .insert(sender_address.clone(), contract_state.clone());

        let state = CachedState::new(state_reader, Some(contract_class_cache));

        //* --------------------------------------------
        //*    Create starknet state with previous data
        //* --------------------------------------------

        let mut starknet_state = StarknetState::new(None);

        starknet_state.state = state;
        starknet_state
            .state
            .state_reader
            .contract_states
            .insert(Address(1.into()), contract_state);

        // --------------------------------------------
        //      Test declare with starknet state
        // --------------------------------------------
        let fib_path = PathBuf::from("starknet_programs/fibonacci.json");
        let fib_contract_class = ContractClass::try_from(fib_path).unwrap();

        let (ret_class_hash, _exec_info) =
            starknet_state.declare(fib_contract_class.clone()).unwrap();

        //* ---------------------------------------
        //              Expected result
        //* ---------------------------------------

        // ----- calculate fib class hash ---------
        let hash = compute_class_hash(&fib_contract_class).unwrap();
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
                .contract_classes
                .unwrap()
                .get(&fib_class_hash)
                .unwrap()
                .to_owned(),
            fib_contract_class
        );
    }
}
