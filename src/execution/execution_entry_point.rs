use std::fmt;
use std::sync::Arc;

use crate::core::errors::state_errors::StateError;
use crate::services::api::contract_classes::deprecated_contract_class::{
    ContractEntryPoint, EntryPointType,
};
use crate::state::cached_state::CachedState;
use crate::state::StateDiff;
use crate::{
    definitions::{block_context::BlockContext, constants::DEFAULT_ENTRY_POINT_SELECTOR},
    runner::StarknetRunner,
    services::api::contract_classes::{
        compiled_class::CompiledClass, deprecated_contract_class::ContractClass,
    },
    state::state_api::State,
    state::ExecutionResourcesManager,
    state::{contract_storage_state::ContractStorageState, state_api::StateReader},
    syscalls::{
        business_logic_syscall_handler::BusinessLogicSyscallHandler,
        deprecated_business_logic_syscall_handler::DeprecatedBLSyscallHandler,
        deprecated_syscall_handler::DeprecatedSyscallHintProcessor,
        syscall_handler::SyscallHintProcessor,
    },
    transaction::error::TransactionError,
    utils::{
        get_deployed_address_class_hash_at_address, parse_builtin_names,
        validate_contract_deployed, Address,
    },
};
use cairo_lang_sierra::ProgramParser;
use cairo_lang_starknet::casm_contract_class::{CasmContractClass, CasmContractEntryPoint};
use cairo_lang_starknet::contract;
use cairo_native::context::NativeContext;
use cairo_native::executor::NativeExecutor;
use cairo_native::metadata::syscall_handler::SyscallHandlerMeta;
use cairo_native::starknet::{
    BlockInfo, ExecutionInfo, StarkNetSyscallHandler, SyscallResult, TxInfo, U256,
};
use cairo_native::utils::{felt252_bigint, felt252_short_str, find_function_id};
use cairo_vm::{
    felt::Felt252,
    types::{
        program::Program,
        relocatable::{MaybeRelocatable, Relocatable},
    },
    vm::{
        runners::cairo_runner::{CairoArg, CairoRunner, ExecutionResources, RunResources},
        vm_core::VirtualMachine,
    },
};
use num_traits::Zero;
use serde::de::SeqAccess;
use serde::{de, Deserialize, Deserializer};
use serde_json::{json, Value};

use super::{
    CallInfo, CallResult, CallType, OrderedEvent, OrderedL2ToL1Message, TransactionExecutionContext,
};

#[derive(Debug)]
pub struct NativeExecutionResult {
    pub gas_builtin: Option<u64>,
    pub range_check: Option<u64>,
    pub system: Option<u64>,
    pub failure_flag: bool,
    pub return_values: Vec<Felt252>,
}

impl<'de> Deserialize<'de> for NativeExecutionResult {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct NativeExecutionResultVisitor;

        impl<'de> de::Visitor<'de> for NativeExecutionResultVisitor {
            type Value = NativeExecutionResult;

            fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
                formatter.write_str("Could not deserialize array of hexadecimal")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let (mut failure_flag_integer, mut return_values): (u64, Vec<Vec<Vec<Vec<u32>>>>) =
                    (0, vec![]);
                let mut last_element: Option<Value> = None;
                while let Some(value) = seq.next_element::<Option<Value>>()? {
                    last_element = value;
                }

                let (mut failure_flag_integer, mut return_values): (u64, Vec<Vec<Vec<Vec<u32>>>>) =
                    serde_json::from_value::<(u64, Vec<Vec<Vec<Vec<u32>>>>)>(last_element.unwrap())
                        .unwrap();

                Ok(NativeExecutionResult {
                    gas_builtin: None,
                    range_check: None,
                    system: None,
                    return_values: return_values[0][0]
                        .iter()
                        .map(|felt_bytes| u32_vec_to_felt(felt_bytes))
                        .collect(),
                    failure_flag: failure_flag_integer == 1,
                })
            }
        }

        const FIELDS: &'static [&'static str] = &[
            "gas_builtin",
            "range_check",
            "system",
            "return_values",
            "failure_flag",
        ];
        deserializer.deserialize_struct("Duration", FIELDS, NativeExecutionResultVisitor)
    }
}

fn u32_vec_to_felt(u32_limbs: &[u32]) -> Felt252 {
    let mut ret = vec![];

    for limb in u32_limbs {
        let bytes = limb.to_be_bytes();
        ret.extend_from_slice(&bytes);
    }

    Felt252::from_bytes_be(&ret)
}

#[derive(Debug)]
struct SyscallHandler<'a, S>
where
    S: StateReader,
{
    pub(crate) starknet_storage_state: ContractStorageState<'a, S>,
    pub(crate) contract_address: Address,
    pub(crate) events: Vec<OrderedEvent>,
    pub(crate) n_emitted_events: u64,
    pub(crate) n_sent_messages: usize,
    pub(crate) l2_to_l1_messages: Vec<OrderedL2ToL1Message>,
    // TODO: This may not be really needed for Cairo Native, just passing
    // it to be able to call the `execute` method of ExecutionEntrypoint.
    pub(crate) internal_calls: Vec<CallInfo>,
}

impl<'a, S: StateReader> StarkNetSyscallHandler for SyscallHandler<'a, S> {
    fn get_block_hash(&self, block_number: u64) -> SyscallResult<cairo_vm::felt::Felt252> {
        println!("Called `get_block_hash({block_number})` from MLIR.");
        Ok(Felt252::from_bytes_be(b"get_block_hash ok"))
    }

    fn get_execution_info(&self) -> SyscallResult<cairo_native::starknet::ExecutionInfo> {
        println!("Called `get_execution_info()` from MLIR.");
        Ok(ExecutionInfo {
            block_info: BlockInfo {
                block_number: 1234,
                block_timestamp: 2345,
                sequencer_address: 3456.into(),
            },
            tx_info: TxInfo {
                version: 4567.into(),
                account_contract_address: 5678.into(),
                max_fee: 6789,
                signature: vec![1248.into(), 2486.into()],
                transaction_hash: 9876.into(),
                chain_id: 8765.into(),
                nonce: 7654.into(),
            },
            caller_address: 6543.into(),
            contract_address: 5432.into(),
            entry_point_selector: 4321.into(),
        })
    }

    fn deploy(
        &self,
        class_hash: cairo_vm::felt::Felt252,
        contract_address_salt: cairo_vm::felt::Felt252,
        calldata: &[cairo_vm::felt::Felt252],
        deploy_from_zero: bool,
    ) -> SyscallResult<(cairo_vm::felt::Felt252, Vec<cairo_vm::felt::Felt252>)> {
        println!("Called `deploy({class_hash}, {contract_address_salt}, {calldata:?}, {deploy_from_zero})` from MLIR.");
        Ok((
            class_hash + contract_address_salt,
            calldata.iter().map(|x| x + &Felt252::new(1)).collect(),
        ))
    }

    fn replace_class(&self, class_hash: cairo_vm::felt::Felt252) -> SyscallResult<()> {
        println!("Called `replace_class({class_hash})` from MLIR.");
        Ok(())
    }

    fn library_call(
        &self,
        class_hash: cairo_vm::felt::Felt252,
        function_selector: cairo_vm::felt::Felt252,
        calldata: &[cairo_vm::felt::Felt252],
    ) -> SyscallResult<Vec<cairo_vm::felt::Felt252>> {
        println!(
            "Called `library_call({class_hash}, {function_selector}, {calldata:?})` from MLIR."
        );
        Ok(calldata.iter().map(|x| x * &Felt252::new(3)).collect())
    }

    fn call_contract(
        &mut self,
        address: cairo_vm::felt::Felt252,
        entrypoint_selector: cairo_vm::felt::Felt252,
        calldata: &[cairo_vm::felt::Felt252],
    ) -> SyscallResult<Vec<cairo_vm::felt::Felt252>> {
        println!(
            "Called `call_contract({address}, {entrypoint_selector}, {calldata:?})` from MLIR."
        );
        let address = Address(address);
        let exec_entry_point = ExecutionEntryPoint::new(
            address,
            calldata.to_vec(),
            entrypoint_selector,
            self.contract_address.clone(),
            EntryPointType::External,
            Some(CallType::Call),
            None,
            // TODO: The remaining gas must be correctly set someway
            u128::MAX,
        );

        let ExecutionResult {
            call_info,
            revert_error,
            ..
        } = exec_entry_point
            .execute(
                self.starknet_storage_state.state,
                // TODO: This fields dont make much sense in the Cairo Native context,
                // they are only dummy values for the `execute` method.
                &BlockContext::default(),
                &mut ExecutionResourcesManager::default(),
                &mut TransactionExecutionContext::default(),
                false,
                u64::MAX,
            )
            .unwrap();

        let call_info = call_info.unwrap();

        // update syscall handler information
        self.starknet_storage_state
            .read_values
            .extend(call_info.storage_read_values.clone());
        self.starknet_storage_state
            .accessed_keys
            .extend(call_info.accessed_storage_keys.clone());
        self.internal_calls.push(call_info);

        Ok(call_info.retdata)
    }

    fn storage_read(
        &mut self,
        address_domain: u32,
        address: cairo_vm::felt::Felt252,
    ) -> SyscallResult<cairo_vm::felt::Felt252> {
        println!("Called `storage_read({address_domain}, {address})` from MLIR.");
        match self.starknet_storage_state.read(&address.to_be_bytes()) {
            Ok(value) => Ok(value),
            Err(_e @ StateError::Io(_)) => todo!(),
            Err(_) => Ok(Felt252::zero()),
        }
    }

    fn storage_write(
        &mut self,
        address_domain: u32,
        address: cairo_vm::felt::Felt252,
        value: cairo_vm::felt::Felt252,
    ) -> SyscallResult<()> {
        println!("Called `storage_write({address_domain}, {address}, {value})` from MLIR.");
        Ok(self
            .starknet_storage_state
            .write(&address.to_be_bytes(), value))
    }

    fn emit_event(
        &mut self,
        keys: &[cairo_vm::felt::Felt252],
        data: &[cairo_vm::felt::Felt252],
    ) -> SyscallResult<()> {
        let order = self.n_emitted_events;
        println!("Called `emit_event(KEYS: {keys:?}, DATA: {data:?})` from MLIR.");
        self.events
            .push(OrderedEvent::new(order, keys.to_vec(), data.to_vec()));
        self.n_emitted_events += 1;
        Ok(())
    }

    fn send_message_to_l1(
        &mut self,
        to_address: cairo_vm::felt::Felt252,
        payload: &[cairo_vm::felt::Felt252],
    ) -> SyscallResult<()> {
        println!("Called `send_message_to_l1({to_address}, {payload:?})` from MLIR.");
        let addr = Address(to_address);
        self.l2_to_l1_messages.push(OrderedL2ToL1Message::new(
            self.n_sent_messages,
            addr,
            payload.to_vec(),
        ));

        // Update messages count.
        self.n_sent_messages += 1;
        Ok(())
    }

    fn keccak(&self, input: &[u64]) -> SyscallResult<cairo_native::starknet::U256> {
        println!("Called `keccak({input:?})` from MLIR.");
        Ok(U256(Felt252::from(1234567890).to_le_bytes()))
    }

    fn secp256k1_add(
        &self,
        _p0: cairo_native::starknet::Secp256k1Point,
        _p1: cairo_native::starknet::Secp256k1Point,
    ) -> SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!()
    }

    fn secp256k1_get_point_from_x(
        &self,
        _x: cairo_native::starknet::U256,
        _y_parity: bool,
    ) -> SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!()
    }

    fn secp256k1_get_xy(
        &self,
        _p: cairo_native::starknet::Secp256k1Point,
    ) -> SyscallResult<(cairo_native::starknet::U256, cairo_native::starknet::U256)> {
        todo!()
    }

    fn secp256k1_mul(
        &self,
        _p: cairo_native::starknet::Secp256k1Point,
        _m: cairo_native::starknet::U256,
    ) -> SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!()
    }

    fn secp256k1_new(
        &self,
        _x: cairo_native::starknet::U256,
        _y: cairo_native::starknet::U256,
    ) -> SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!()
    }

    fn secp256r1_add(
        &self,
        _p0: cairo_native::starknet::Secp256k1Point,
        _p1: cairo_native::starknet::Secp256k1Point,
    ) -> SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!()
    }

    fn secp256r1_get_point_from_x(
        &self,
        _x: cairo_native::starknet::U256,
        _y_parity: bool,
    ) -> SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!()
    }

    fn secp256r1_get_xy(
        &self,
        _p: cairo_native::starknet::Secp256k1Point,
    ) -> SyscallResult<(cairo_native::starknet::U256, cairo_native::starknet::U256)> {
        todo!()
    }

    fn secp256r1_mul(
        &self,
        _p: cairo_native::starknet::Secp256k1Point,
        _m: cairo_native::starknet::U256,
    ) -> SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!()
    }

    fn secp256r1_new(
        &self,
        _x: cairo_native::starknet::U256,
        _y: cairo_native::starknet::U256,
    ) -> SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!()
    }

    fn pop_log(&self) {
        todo!()
    }

    fn set_account_contract_address(&self, _contract_address: cairo_vm::felt::Felt252) {
        todo!()
    }

    fn set_block_number(&self, _block_number: u64) {
        todo!()
    }

    fn set_block_timestamp(&self, _block_timestamp: u64) {
        todo!()
    }

    fn set_caller_address(&self, _address: cairo_vm::felt::Felt252) {
        todo!()
    }

    fn set_chain_id(&self, _chain_id: cairo_vm::felt::Felt252) {
        todo!()
    }

    fn set_contract_address(&self, _address: cairo_vm::felt::Felt252) {
        todo!()
    }

    fn set_max_fee(&self, _max_fee: u128) {
        todo!()
    }

    fn set_nonce(&self, _nonce: cairo_vm::felt::Felt252) {
        todo!()
    }

    fn set_sequencer_address(&self, _address: cairo_vm::felt::Felt252) {
        todo!()
    }

    fn set_signature(&self, _signature: &[cairo_vm::felt::Felt252]) {
        todo!()
    }

    fn set_transaction_hash(&self, _transaction_hash: cairo_vm::felt::Felt252) {
        todo!()
    }

    fn set_version(&self, _version: cairo_vm::felt::Felt252) {
        todo!()
    }
}

#[derive(Debug, Default)]
pub struct ExecutionResult {
    pub call_info: Option<CallInfo>,
    pub revert_error: Option<String>,
    pub n_reverted_steps: usize,
}

/// Represents a Cairo entry point execution of a StarkNet contract.

// TODO:initial_gas is a new field added in the current changes, it should be checked if we delete it once the new execution entry point is done
#[derive(Debug, Clone)]
pub struct ExecutionEntryPoint {
    pub(crate) call_type: CallType,
    pub(crate) contract_address: Address,
    pub(crate) code_address: Option<Address>,
    pub(crate) class_hash: Option<[u8; 32]>,
    pub(crate) calldata: Vec<Felt252>,
    pub(crate) caller_address: Address,
    pub(crate) entry_point_selector: Felt252,
    pub(crate) entry_point_type: EntryPointType,
    pub(crate) initial_gas: u128,
}
#[allow(clippy::too_many_arguments)]
impl ExecutionEntryPoint {
    pub fn new(
        contract_address: Address,
        calldata: Vec<Felt252>,
        entry_point_selector: Felt252,
        caller_address: Address,
        entry_point_type: EntryPointType,
        call_type: Option<CallType>,
        class_hash: Option<[u8; 32]>,
        initial_gas: u128,
    ) -> Self {
        ExecutionEntryPoint {
            call_type: call_type.unwrap_or(CallType::Call),
            contract_address,
            code_address: None,
            class_hash,
            calldata,
            caller_address,
            entry_point_selector,
            entry_point_type,
            initial_gas,
        }
    }

    /// Executes the selected entry point with the given calldata in the specified contract.
    /// The information collected from this run (number of steps required, modifications to the
    /// contract storage, etc.) is saved on the resources manager.
    /// Returns a CallInfo object that represents the execution.
    pub fn execute<T>(
        &self,
        state: &mut CachedState<T>,
        block_context: &BlockContext,
        resources_manager: &mut ExecutionResourcesManager,
        tx_execution_context: &mut TransactionExecutionContext,
        support_reverted: bool,
        max_steps: u64,
    ) -> Result<ExecutionResult, TransactionError>
    where
        T: StateReader,
    {
        // lookup the compiled class from the state.
        let class_hash = self.get_code_class_hash(state)?;
        let contract_class = state
            .get_contract_class(&class_hash)
            .map_err(|_| TransactionError::MissingCompiledClass)?;
        match contract_class {
            CompiledClass::Deprecated(contract_class) => {
                let call_info = self._execute_version0_class(
                    state,
                    resources_manager,
                    block_context,
                    tx_execution_context,
                    contract_class,
                    class_hash,
                )?;
                Ok(ExecutionResult {
                    call_info: Some(call_info),
                    revert_error: None,
                    n_reverted_steps: 0,
                })
            }
            CompiledClass::Casm(contract_class) => {
                let mut tmp_state = CachedState::new(state.state_reader.clone());
                if let Some(contract_classes_cache) = &state.contract_classes {
                    tmp_state =
                        tmp_state.set_contract_classes_cache(contract_classes_cache.clone());
                }
                if let Some(casm_classes_cache) = &state.casm_contract_classes {
                    tmp_state = tmp_state.set_casm_classes_cache(casm_classes_cache.clone());
                }
                tmp_state.cache = state.cache.clone();

                match self._execute(
                    &mut tmp_state,
                    resources_manager,
                    block_context,
                    tx_execution_context,
                    contract_class,
                    class_hash,
                    support_reverted,
                ) {
                    Ok(call_info) => {
                        let state_diff = StateDiff::from_cached_state(tmp_state)?;
                        state.apply_state_update(&state_diff)?;
                        Ok(ExecutionResult {
                            call_info: Some(call_info),
                            revert_error: None,
                            n_reverted_steps: 0,
                        })
                    }
                    Err(e) => {
                        if !support_reverted {
                            return Err(e);
                        }

                        let n_reverted_steps =
                            (max_steps as usize) - resources_manager.cairo_usage.n_steps;
                        Ok(ExecutionResult {
                            call_info: None,
                            revert_error: Some(e.to_string()),
                            n_reverted_steps,
                        })
                    }
                }
            }
            CompiledClass::Sierra(contract_class) => {
                let mut tmp_state = CachedState::new(state.state_reader.clone());
                if let Some(sierra_programs_cache) = &state.sierra_programs {
                    tmp_state = tmp_state.set_sierra_programs_cache(sierra_programs_cache.clone());
                }
                tmp_state.cache = state.cache.clone();

                match self.native_execute(&mut tmp_state, contract_class) {
                    Ok(call_info) => {
                        let state_diff = StateDiff::from_cached_state(tmp_state)?;
                        state.apply_state_update(&state_diff)?;
                        return Ok(ExecutionResult {
                            call_info: Some(call_info),
                            revert_error: None,
                            n_reverted_steps: 0,
                        });
                    }
                    Err(e) => {
                        if !support_reverted {
                            return Err(e);
                        }

                        let n_reverted_steps =
                            (max_steps as usize) - resources_manager.cairo_usage.n_steps;
                        return Ok(ExecutionResult {
                            call_info: None,
                            revert_error: Some(e.to_string()),
                            n_reverted_steps,
                        });
                    }
                }
            }
        }
    }

    /// Returns the entry point with selector corresponding with self.entry_point_selector, or the
    /// default if there is one and the requested one is not found.
    fn get_selected_entry_point_v0(
        &self,
        contract_class: &ContractClass,
        _class_hash: [u8; 32],
    ) -> Result<ContractEntryPoint, TransactionError> {
        let entry_points = contract_class
            .entry_points_by_type
            .get(&self.entry_point_type)
            .ok_or(TransactionError::InvalidEntryPoints)?;

        let mut default_entry_point = None;
        let entry_point = entry_points
            .iter()
            .filter_map(|x| {
                if x.selector() == &*DEFAULT_ENTRY_POINT_SELECTOR {
                    default_entry_point = Some(x);
                }

                (x.selector() == &self.entry_point_selector).then_some(x)
            })
            .fold(Ok(None), |acc, x| match acc {
                Ok(None) => Ok(Some(x)),
                _ => Err(TransactionError::NonUniqueEntryPoint),
            })?;

        entry_point
            .or(default_entry_point)
            .cloned()
            .ok_or(TransactionError::EntryPointNotFound)
    }

    fn get_selected_entry_point(
        &self,
        contract_class: &CasmContractClass,
        _class_hash: [u8; 32],
    ) -> Result<CasmContractEntryPoint, TransactionError> {
        let entry_points = match self.entry_point_type {
            EntryPointType::External => &contract_class.entry_points_by_type.external,
            EntryPointType::Constructor => &contract_class.entry_points_by_type.constructor,
            EntryPointType::L1Handler => &contract_class.entry_points_by_type.l1_handler,
        };

        let mut default_entry_point = None;
        let entry_point = entry_points
            .iter()
            .filter_map(|x| {
                if x.selector == DEFAULT_ENTRY_POINT_SELECTOR.to_biguint() {
                    default_entry_point = Some(x);
                }

                (x.selector == self.entry_point_selector.to_biguint()).then_some(x)
            })
            .fold(Ok(None), |acc, x| match acc {
                Ok(None) => Ok(Some(x)),
                _ => Err(TransactionError::NonUniqueEntryPoint),
            })?;
        entry_point
            .or(default_entry_point)
            .cloned()
            .ok_or(TransactionError::EntryPointNotFound)
    }

    fn build_call_info_deprecated<S: StateReader>(
        &self,
        previous_cairo_usage: ExecutionResources,
        resources_manager: &ExecutionResourcesManager,
        starknet_storage_state: ContractStorageState<S>,
        events: Vec<OrderedEvent>,
        l2_to_l1_messages: Vec<OrderedL2ToL1Message>,
        internal_calls: Vec<CallInfo>,
        retdata: Vec<Felt252>,
    ) -> Result<CallInfo, TransactionError> {
        let execution_resources = &resources_manager.cairo_usage - &previous_cairo_usage;

        Ok(CallInfo {
            caller_address: self.caller_address.clone(),
            call_type: Some(self.call_type.clone()),
            contract_address: self.contract_address.clone(),
            code_address: self.code_address.clone(),
            class_hash: Some(self.get_code_class_hash(starknet_storage_state.state)?),
            entry_point_selector: Some(self.entry_point_selector.clone()),
            entry_point_type: Some(self.entry_point_type),
            calldata: self.calldata.clone(),
            retdata,
            execution_resources: Some(execution_resources.filter_unused_builtins()),
            events,
            l2_to_l1_messages,
            storage_read_values: starknet_storage_state.read_values,
            accessed_storage_keys: starknet_storage_state.accessed_keys,
            internal_calls,
            failure_flag: false,
            gas_consumed: 0,
        })
    }

    fn build_call_info<S: StateReader>(
        &self,
        previous_cairo_usage: ExecutionResources,
        resources_manager: &ExecutionResourcesManager,
        starknet_storage_state: ContractStorageState<S>,
        events: Vec<OrderedEvent>,
        l2_to_l1_messages: Vec<OrderedL2ToL1Message>,
        internal_calls: Vec<CallInfo>,
        call_result: CallResult,
    ) -> Result<CallInfo, TransactionError> {
        let execution_resources = &resources_manager.cairo_usage - &previous_cairo_usage;

        Ok(CallInfo {
            caller_address: self.caller_address.clone(),
            call_type: Some(self.call_type.clone()),
            contract_address: self.contract_address.clone(),
            code_address: self.code_address.clone(),
            class_hash: Some(self.get_code_class_hash(starknet_storage_state.state)?),
            entry_point_selector: Some(self.entry_point_selector.clone()),
            entry_point_type: Some(self.entry_point_type),
            calldata: self.calldata.clone(),
            retdata: call_result
                .retdata
                .iter()
                .map(|n| n.get_int_ref().cloned().unwrap_or_default())
                .collect(),
            execution_resources: Some(execution_resources.filter_unused_builtins()),
            events,
            l2_to_l1_messages,
            storage_read_values: starknet_storage_state.read_values,
            accessed_storage_keys: starknet_storage_state.accessed_keys,
            internal_calls,
            failure_flag: !call_result.is_success,
            gas_consumed: call_result.gas_consumed,
        })
    }

    /// Returns the hash of the executed contract class.
    fn get_code_class_hash<S: State>(&self, state: &mut S) -> Result<[u8; 32], TransactionError> {
        if self.class_hash.is_some() {
            match self.call_type {
                CallType::Delegate => return Ok(self.class_hash.unwrap()),
                _ => return Err(TransactionError::CallTypeIsNotDelegate),
            }
        }
        let code_address = match self.call_type {
            CallType::Call => Some(self.contract_address.clone()),
            CallType::Delegate => {
                if self.code_address.is_some() {
                    self.code_address.clone()
                } else {
                    return Err(TransactionError::AttempToUseNoneCodeAddress);
                }
            }
        };

        get_deployed_address_class_hash_at_address(state, &code_address.unwrap())
    }

    fn _execute_version0_class<S: StateReader>(
        &self,
        state: &mut CachedState<S>,
        resources_manager: &mut ExecutionResourcesManager,
        block_context: &BlockContext,
        tx_execution_context: &mut TransactionExecutionContext,
        contract_class: Arc<ContractClass>,
        class_hash: [u8; 32],
    ) -> Result<CallInfo, TransactionError> {
        let previous_cairo_usage = resources_manager.cairo_usage.clone();
        // fetch selected entry point
        let entry_point = self.get_selected_entry_point_v0(&contract_class, class_hash)?;

        // create starknet runner
        let mut vm = VirtualMachine::new(false);
        let mut cairo_runner = CairoRunner::new(&contract_class.program, "starknet", false)?;
        cairo_runner.initialize_function_runner(&mut vm)?;

        validate_contract_deployed(state, &self.contract_address)?;

        // prepare OS context
        //let os_context = runner.prepare_os_context();
        let os_context =
            StarknetRunner::<DeprecatedSyscallHintProcessor<S>>::prepare_os_context_cairo0(
                &cairo_runner,
                &mut vm,
            );

        // fetch syscall_ptr
        let initial_syscall_ptr: Relocatable = match os_context.get(0) {
            Some(MaybeRelocatable::RelocatableValue(ptr)) => ptr.to_owned(),
            _ => return Err(TransactionError::NotARelocatableValue),
        };

        let syscall_handler = DeprecatedBLSyscallHandler::new(
            tx_execution_context.clone(),
            state,
            resources_manager.clone(),
            self.caller_address.clone(),
            self.contract_address.clone(),
            block_context.clone(),
            initial_syscall_ptr,
        );
        let hint_processor =
            DeprecatedSyscallHintProcessor::new(syscall_handler, RunResources::default());
        let mut runner = StarknetRunner::new(cairo_runner, vm, hint_processor);

        // Positional arguments are passed to *args in the 'run_from_entrypoint' function.
        let data: Vec<MaybeRelocatable> = self.calldata.iter().map(|d| d.into()).collect();
        let alloc_pointer = runner
            .hint_processor
            .syscall_handler
            .allocate_segment(&mut runner.vm, data)?
            .into();

        let entry_point_args = [
            &CairoArg::Single(self.entry_point_selector.clone().into()),
            &CairoArg::Array(os_context.clone()),
            &CairoArg::Single(MaybeRelocatable::Int(self.calldata.len().into())),
            &CairoArg::Single(alloc_pointer),
        ];

        // cairo runner entry point
        runner.run_from_entrypoint(entry_point.offset(), &entry_point_args, None)?;
        runner.validate_and_process_os_context_for_version0_class(os_context)?;

        // When execution starts the stack holds entry_points_args + [ret_fp, ret_pc].
        let args_ptr = (runner
            .cairo_runner
            .get_initial_fp()
            .ok_or(TransactionError::MissingInitialFp)?
            - (entry_point_args.len() + 2))?;

        runner
            .vm
            .mark_address_range_as_accessed(args_ptr, entry_point_args.len())?;

        *resources_manager = runner
            .hint_processor
            .syscall_handler
            .resources_manager
            .clone();

        *tx_execution_context = runner
            .hint_processor
            .syscall_handler
            .tx_execution_context
            .clone();

        // Update resources usage (for bouncer).
        resources_manager.cairo_usage += &runner.get_execution_resources()?;

        let retdata = runner.get_return_values()?;

        self.build_call_info_deprecated::<S>(
            previous_cairo_usage,
            resources_manager,
            runner.hint_processor.syscall_handler.starknet_storage_state,
            runner.hint_processor.syscall_handler.events,
            runner.hint_processor.syscall_handler.l2_to_l1_messages,
            runner.hint_processor.syscall_handler.internal_calls,
            retdata,
        )
    }

    fn _execute<S: StateReader>(
        &self,
        state: &mut CachedState<S>,
        resources_manager: &mut ExecutionResourcesManager,
        block_context: &BlockContext,
        tx_execution_context: &mut TransactionExecutionContext,
        contract_class: Arc<CasmContractClass>,
        class_hash: [u8; 32],
        support_reverted: bool,
    ) -> Result<CallInfo, TransactionError> {
        let previous_cairo_usage = resources_manager.cairo_usage.clone();

        // fetch selected entry point
        let entry_point = self.get_selected_entry_point(&contract_class, class_hash)?;

        // create starknet runner
        let mut vm = VirtualMachine::new(false);
        // get a program from the casm contract class
        let program: Program = contract_class.as_ref().clone().try_into()?;
        // create and initialize a cairo runner for running cairo 1 programs.
        let mut cairo_runner = CairoRunner::new(&program, "starknet", false)?;

        cairo_runner.initialize_function_runner_cairo_1(
            &mut vm,
            &parse_builtin_names(&entry_point.builtins)?,
        )?;
        validate_contract_deployed(state, &self.contract_address)?;
        // prepare OS context
        let os_context = StarknetRunner::<SyscallHintProcessor<S>>::prepare_os_context_cairo1(
            &cairo_runner,
            &mut vm,
            self.initial_gas.into(),
        );

        // fetch syscall_ptr (it is the last element of the os_context)
        let initial_syscall_ptr: Relocatable = match os_context.last() {
            Some(MaybeRelocatable::RelocatableValue(ptr)) => ptr.to_owned(),
            _ => return Err(TransactionError::NotARelocatableValue),
        };

        let syscall_handler = BusinessLogicSyscallHandler::new(
            tx_execution_context.clone(),
            state,
            resources_manager.clone(),
            self.caller_address.clone(),
            self.contract_address.clone(),
            block_context.clone(),
            initial_syscall_ptr,
            support_reverted,
            self.entry_point_selector.clone(),
        );
        // create and attach a syscall hint processor to the starknet runner.
        let hint_processor = SyscallHintProcessor::new(
            syscall_handler,
            &contract_class.hints,
            RunResources::default(),
        );
        let mut runner = StarknetRunner::new(cairo_runner, vm, hint_processor);

        // TODO: handle error cases
        // Load builtin costs
        let builtin_costs: Vec<MaybeRelocatable> =
            vec![0.into(), 0.into(), 0.into(), 0.into(), 0.into()];
        let builtin_costs_ptr: MaybeRelocatable = runner
            .hint_processor
            .syscall_handler
            .allocate_segment(&mut runner.vm, builtin_costs)?
            .into();

        // Load extra data
        let core_program_end_ptr =
            (runner.cairo_runner.program_base.unwrap() + program.data_len()).unwrap();
        let program_extra_data: Vec<MaybeRelocatable> =
            vec![0x208B7FFF7FFF7FFE.into(), builtin_costs_ptr];
        runner
            .vm
            .load_data(core_program_end_ptr, &program_extra_data)
            .unwrap();

        // Positional arguments are passed to *args in the 'run_from_entrypoint' function.
        let data = self.calldata.iter().map(|d| d.into()).collect();
        let alloc_pointer: MaybeRelocatable = runner
            .hint_processor
            .syscall_handler
            .allocate_segment(&mut runner.vm, data)?
            .into();

        let mut entrypoint_args: Vec<CairoArg> = os_context
            .iter()
            .map(|x| CairoArg::Single(x.into()))
            .collect();
        entrypoint_args.push(CairoArg::Single(alloc_pointer.clone()));
        entrypoint_args.push(CairoArg::Single(
            alloc_pointer.add_usize(self.calldata.len()).unwrap(),
        ));

        let ref_vec: Vec<&CairoArg> = entrypoint_args.iter().collect();

        // run the Cairo1 entrypoint
        runner.run_from_entrypoint(
            entry_point.offset,
            &ref_vec,
            Some(program.data_len() + program_extra_data.len()),
        )?;

        runner
            .vm
            .mark_address_range_as_accessed(core_program_end_ptr, program_extra_data.len())?;

        runner.validate_and_process_os_context(os_context)?;

        // When execution starts the stack holds entry_points_args + [ret_fp, ret_pc].
        let initial_fp = runner
            .cairo_runner
            .get_initial_fp()
            .ok_or(TransactionError::MissingInitialFp)?;

        let args_ptr = initial_fp - (entrypoint_args.len() + 2);

        runner
            .vm
            .mark_address_range_as_accessed(args_ptr.unwrap(), entrypoint_args.len())?;

        *resources_manager = runner
            .hint_processor
            .syscall_handler
            .resources_manager
            .clone();

        *tx_execution_context = runner
            .hint_processor
            .syscall_handler
            .tx_execution_context
            .clone();

        // Update resources usage (for bouncer).
        resources_manager.cairo_usage += &runner.get_execution_resources()?;

        let call_result = runner.get_call_result(self.initial_gas)?;
        self.build_call_info::<S>(
            previous_cairo_usage,
            resources_manager,
            runner.hint_processor.syscall_handler.starknet_storage_state,
            runner.hint_processor.syscall_handler.events,
            runner.hint_processor.syscall_handler.l2_to_l1_messages,
            runner.hint_processor.syscall_handler.internal_calls,
            call_result,
        )
    }

    fn native_execute<S: StateReader>(
        &self,
        state: &mut CachedState<S>,
        contract_class: Arc<cairo_lang_starknet::contract_class::ContractClass>,
    ) -> Result<CallInfo, TransactionError> {
        let entry_point = match self.entry_point_type {
            EntryPointType::External => contract_class
                .entry_points_by_type
                .external
                .iter()
                .find(|entry_point| entry_point.selector == self.entry_point_selector.to_biguint())
                .unwrap(),
            EntryPointType::Constructor => contract_class
                .entry_points_by_type
                .constructor
                .iter()
                .find(|entry_point| entry_point.selector == self.entry_point_selector.to_biguint())
                .unwrap(),
            EntryPointType::L1Handler => contract_class
                .entry_points_by_type
                .l1_handler
                .iter()
                .find(|entry_point| entry_point.selector == self.entry_point_selector.to_biguint())
                .unwrap(),
        };

        let sierra_program = contract_class.extract_sierra_program().unwrap();

        let native_context = NativeContext::new();
        let mut native_program = native_context.compile(&sierra_program).unwrap();
        let contract_storage_state =
            ContractStorageState::new(state, self.contract_address.clone());

        let contract_address = Address(1.into());

        let mut syscall_handler = SyscallHandler {
            starknet_storage_state: contract_storage_state,
            n_emitted_events: 0,
            events: Vec::new(),
            l2_to_l1_messages: Vec::new(),
            n_sent_messages: 0,
            contract_address,
            internal_calls: Vec::new(),
        };
        native_program
            .insert_metadata(SyscallHandlerMeta::new(&mut syscall_handler))
            .unwrap();

        let syscall_addr = native_program
            .get_metadata::<SyscallHandlerMeta>()
            .unwrap()
            .as_ptr()
            .addr();

        let fn_id = &sierra_program
            .funcs
            .iter()
            .find(|x| x.id.id == (entry_point.function_idx as u64))
            .unwrap()
            .id;

        let required_init_gas = native_program.get_required_init_gas(fn_id);

        let calldata: Vec<_> = self
            .calldata
            .iter()
            .map(|felt| felt252_bigint(felt.to_bigint()))
            .collect();

        let params = match self.entry_point_type {
            EntryPointType::External => {
                json!([
                    (),
                    // gas
                    u64::MAX,
                    // system
                    syscall_addr,
                    [
                        // Span<Array<felt>>
                        calldata
                    ]
                ])
            }
            EntryPointType::L1Handler => {
                json!([
                    (),
                    // gas
                    u64::MAX,
                    // system
                    syscall_addr,
                    [
                        // Span<Array<felt>>
                        calldata
                    ]
                ])
            }
            EntryPointType::Constructor => {
                json!([
                    // pedersen
                    null,
                    // range check
                    null,
                    // gas
                    u64::MAX,
                    // system
                    syscall_addr,
                    [
                        // Span<Array<felt>>
                        calldata
                    ]
                ])
            }
        };

        println!("SYSCALL ADDRESS: {}", syscall_addr);

        let mut writer: Vec<u8> = Vec::new();
        let returns = &mut serde_json::Serializer::new(&mut writer);

        let native_executor = NativeExecutor::new(native_program);

        native_executor
            .execute(fn_id, params, returns, required_init_gas)
            .unwrap();

        let result: String = String::from_utf8(writer).unwrap();
        let value = serde_json::from_str::<NativeExecutionResult>(&result).unwrap();

        return Ok(CallInfo {
            caller_address: self.caller_address.clone(),
            call_type: Some(self.call_type.clone()),
            contract_address: self.contract_address.clone(),
            code_address: self.code_address.clone(),
            class_hash: Some(
                self.get_code_class_hash(syscall_handler.starknet_storage_state.state)?,
            ),
            entry_point_selector: Some(self.entry_point_selector.clone()),
            entry_point_type: Some(self.entry_point_type),
            calldata: self.calldata.clone(),
            retdata: value.return_values,
            execution_resources: None,
            events: syscall_handler.events,
            storage_read_values: syscall_handler.starknet_storage_state.read_values,
            accessed_storage_keys: syscall_handler.starknet_storage_state.accessed_keys,
            failure_flag: value.failure_flag,
            l2_to_l1_messages: syscall_handler.l2_to_l1_messages,

            // TODO
            internal_calls: vec![],

            // TODO
            gas_consumed: 0,
        });
    }
}

#[test]
fn wallet_increase_and_read() {
    // let increase_fn_id = find_function_id(
    //     &sierra_program,
    //     "wallet::wallet::SimpleWallet::__wrapper_increase_balance",
    //     // "wallet::wallet::SimpleWallet::SimpleWallet::increase_balance",
    // );
    // let increase_required_init_gas = native_program.get_required_init_gas(increase_fn_id);

    // let get_fn_id = find_function_id(
    //     &sierra_program,
    //     "wallet::wallet::SimpleWallet::__wrapper_get_balance",
    // );
    // let get_required_init_gas = native_program.get_required_init_gas(get_fn_id);
}
