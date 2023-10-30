use cairo_native::starknet::{
    BlockInfo, ExecutionInfo, StarkNetSyscallHandler, SyscallResult, TxInfo, U256,
};
use cairo_vm::felt::Felt252;
use num_traits::Zero;

use crate::definitions::constants::CONSTRUCTOR_ENTRY_POINT_SELECTOR;
use crate::execution::CallResult;
use crate::hash_utils::calculate_contract_address;
use crate::services::api::contract_class_errors::ContractClassError;
use crate::services::api::contract_classes::compiled_class::CompiledClass;
use crate::state::state_api::State;
use crate::utils::felt_to_hash;
use crate::utils::ClassHash;
use crate::{
    core::errors::state_errors::StateError,
    definitions::block_context::BlockContext,
    execution::{
        execution_entry_point::{ExecutionEntryPoint, ExecutionResult},
        CallInfo, CallType, OrderedEvent, OrderedL2ToL1Message, TransactionExecutionContext,
    },
    state::{
        contract_storage_state::ContractStorageState, state_api::StateReader,
        ExecutionResourcesManager,
    },
    syscalls::business_logic_syscall_handler::{SYSCALL_BASE, SYSCALL_GAS_COST},
    utils::Address,
    EntryPointType,
};

#[derive(Debug)]
pub struct NativeSyscallHandler<'a, S>
where
    S: StateReader,
{
    pub(crate) starknet_storage_state: ContractStorageState<'a, S>,
    pub(crate) contract_address: Address,
    pub(crate) caller_address: Address,
    pub(crate) entry_point_selector: Felt252,
    pub(crate) events: Vec<OrderedEvent>,
    pub(crate) l2_to_l1_messages: Vec<OrderedL2ToL1Message>,
    pub(crate) tx_execution_context: TransactionExecutionContext,
    pub(crate) block_context: BlockContext,
    pub(crate) internal_calls: Vec<CallInfo>,
    pub(crate) resources_manager: ExecutionResourcesManager,
}

impl<'a, S: StateReader> NativeSyscallHandler<'a, S> {
    /// Generic code that needs to be run on all syscalls.
    fn handle_syscall_request(&mut self, gas: &mut u128, syscall_name: &str) -> SyscallResult<()> {
        let required_gas = SYSCALL_GAS_COST
            .get(syscall_name)
            .map(|&x| x.saturating_sub(SYSCALL_BASE))
            .unwrap_or(0);

        if *gas < required_gas {
            let out_of_gas_felt = Felt252::from_bytes_be("Out of gas".as_bytes());
            println!("out of gas!: {:?} < {:?}", *gas, required_gas); // TODO: remove once all other prints are removed
            return Err(vec![out_of_gas_felt.clone()]);
        }

        *gas = gas.saturating_sub(required_gas);

        self.resources_manager
            .increment_syscall_counter(syscall_name, 1);

        Ok(())
    }
}

impl<'a, S: StateReader> StarkNetSyscallHandler for NativeSyscallHandler<'a, S> {
    fn get_block_hash(
        &mut self,
        block_number: u64,
        gas: &mut u128,
    ) -> SyscallResult<cairo_vm::felt::Felt252> {
        println!("Called `get_block_hash({block_number})` from MLIR.");

        self.handle_syscall_request(gas, "get_block_hash")?;

        let key: Felt252 = block_number.into();
        let block_hash_address = Address(1.into());

        match self
            .starknet_storage_state
            .state
            .get_storage_at(&(block_hash_address, key.to_be_bytes()))
        {
            Ok(value) => Ok(value),
            Err(_) => Ok(Felt252::zero()),
        }
    }

    fn get_execution_info(
        &mut self,
        gas: &mut u128,
    ) -> SyscallResult<cairo_native::starknet::ExecutionInfo> {
        println!("Called `get_execution_info()` from MLIR.");

        self.handle_syscall_request(gas, "get_execution_info")?;

        Ok(ExecutionInfo {
            block_info: BlockInfo {
                block_number: self.block_context.block_info.block_number,
                block_timestamp: self.block_context.block_info.block_timestamp,
                sequencer_address: self.block_context.block_info.sequencer_address.0.clone(),
            },
            tx_info: TxInfo {
                version: self.tx_execution_context.version.clone(),
                account_contract_address: self
                    .tx_execution_context
                    .account_contract_address
                    .0
                    .clone(),
                max_fee: self.tx_execution_context.max_fee,
                signature: self.tx_execution_context.signature.clone(),
                transaction_hash: self.tx_execution_context.transaction_hash.clone(),
                chain_id: self.block_context.starknet_os_config.chain_id.clone(),
                nonce: self.tx_execution_context.nonce.clone(),
            },
            caller_address: self.caller_address.0.clone(),
            contract_address: self.contract_address.0.clone(),
            entry_point_selector: self.entry_point_selector.clone(),
        })
    }

    fn deploy(
        &mut self,
        class_hash: cairo_vm::felt::Felt252,
        contract_address_salt: cairo_vm::felt::Felt252,
        calldata: &[cairo_vm::felt::Felt252],
        deploy_from_zero: bool,
        gas: &mut u128,
    ) -> SyscallResult<(cairo_vm::felt::Felt252, Vec<cairo_vm::felt::Felt252>)> {
        self.handle_syscall_request(gas, "deploy")?;

        let deployer_address = if deploy_from_zero {
            Address::default()
        } else {
            self.contract_address.clone()
        };

        let contract_address = Address(
            calculate_contract_address(
                &contract_address_salt,
                &class_hash,
                calldata,
                deployer_address,
            )
            .map_err(|_| {
                vec![Felt252::from_bytes_be(
                    b"FAILED_TO_CALCULATE_CONTRACT_ADDRESS",
                )]
            })?,
        );
        // Initialize the contract.
        let class_hash_bytes: ClassHash = felt_to_hash(&class_hash);

        self.starknet_storage_state
            .state
            .deploy_contract(contract_address.clone(), class_hash_bytes)
            .map_err(|_| vec![Felt252::from_bytes_be(b"CONTRACT_ADDRESS_UNAVAILABLE")])?;

        let result = self
            .execute_constructor_entry_point(
                &contract_address,
                class_hash_bytes,
                calldata.to_vec(),
                *gas,
            )
            .map_err(|_| vec![Felt252::from_bytes_be(b"CONSTRUCTOR_ENTRYPOINT_FAILURE")])?;

        *gas = gas.saturating_sub(result.gas_consumed);

        Ok((
            contract_address.0,
            result
                .retdata
                .iter()
                .map(|mb| mb.get_int_ref().cloned().unwrap_or_default())
                .collect(),
        ))
    }

    fn replace_class(
        &mut self,
        class_hash: cairo_vm::felt::Felt252,
        gas: &mut u128,
    ) -> SyscallResult<()> {
        println!("Called `replace_class({class_hash})` from MLIR.");

        self.handle_syscall_request(gas, "replace_class")?;
        Ok(())
    }

    fn library_call(
        &mut self,
        class_hash: cairo_vm::felt::Felt252,
        function_selector: cairo_vm::felt::Felt252,
        calldata: &[cairo_vm::felt::Felt252],
        gas: &mut u128,
    ) -> SyscallResult<Vec<cairo_vm::felt::Felt252>> {
        println!(
            "Called `library_call({class_hash}, {function_selector}, {calldata:?})` from MLIR."
        );

        self.handle_syscall_request(gas, "library_call")?;

        Ok(calldata.iter().map(|x| x * &Felt252::new(3)).collect())
    }

    fn call_contract(
        &mut self,
        address: cairo_vm::felt::Felt252,
        entrypoint_selector: cairo_vm::felt::Felt252,
        calldata: &[cairo_vm::felt::Felt252],
        gas: &mut u128,
    ) -> SyscallResult<Vec<cairo_vm::felt::Felt252>> {
        println!(
            "Called `call_contract({address}, {entrypoint_selector}, {calldata:?})` from MLIR."
        );

        self.handle_syscall_request(gas, "call_contract")?;

        let address = Address(address);
        let exec_entry_point = ExecutionEntryPoint::new(
            address,
            calldata.to_vec(),
            entrypoint_selector,
            self.caller_address.clone(),
            EntryPointType::External,
            Some(CallType::Call),
            None,
            *gas,
        );

        let ExecutionResult { call_info, .. } = exec_entry_point
            .execute(
                self.starknet_storage_state.state,
                // TODO: This fields dont make much sense in the Cairo Native context,
                // they are only dummy values for the `execute` method.
                &self.block_context,
                &mut self.resources_manager,
                &mut self.tx_execution_context,
                false,
                self.block_context.invoke_tx_max_n_steps,
            )
            .unwrap();

        let call_info = call_info.unwrap();

        *gas = gas.saturating_sub(call_info.gas_consumed);

        // update syscall handler information
        self.starknet_storage_state
            .read_values
            .extend(call_info.storage_read_values.clone());
        self.starknet_storage_state
            .accessed_keys
            .extend(call_info.accessed_storage_keys.clone());

        let retdata = call_info.retdata.clone();
        self.internal_calls.push(call_info);

        Ok(retdata)
    }

    fn storage_read(
        &mut self,
        address_domain: u32,
        address: cairo_vm::felt::Felt252,
        gas: &mut u128,
    ) -> SyscallResult<cairo_vm::felt::Felt252> {
        println!("Called `storage_read({address_domain}, {address})` from MLIR.");

        self.handle_syscall_request(gas, "storage_read")?;

        let value = match self.starknet_storage_state.read(&address.to_be_bytes()) {
            Ok(value) => Ok(value),
            Err(_e @ StateError::Io(_)) => todo!(),
            Err(_) => Ok(Felt252::zero()),
        };

        println!(" = {value:?}` from MLIR.");

        value
    }

    fn storage_write(
        &mut self,
        address_domain: u32,
        address: cairo_vm::felt::Felt252,
        value: cairo_vm::felt::Felt252,
        gas: &mut u128,
    ) -> SyscallResult<()> {
        println!("Called `storage_write({address_domain}, {address}, {value})` from MLIR.");

        self.handle_syscall_request(gas, "storage_write")?;

        self.starknet_storage_state
            .write(&address.to_be_bytes(), value);
        Ok(())
    }

    fn emit_event(
        &mut self,
        keys: &[cairo_vm::felt::Felt252],
        data: &[cairo_vm::felt::Felt252],
        gas: &mut u128,
    ) -> SyscallResult<()> {
        let order = self.tx_execution_context.n_emitted_events;
        println!("Called `emit_event(KEYS: {keys:?}, DATA: {data:?})` from MLIR.");

        self.handle_syscall_request(gas, "emit_event")?;

        self.events
            .push(OrderedEvent::new(order, keys.to_vec(), data.to_vec()));
        self.tx_execution_context.n_emitted_events += 1;
        Ok(())
    }

    fn send_message_to_l1(
        &mut self,
        to_address: cairo_vm::felt::Felt252,
        payload: &[cairo_vm::felt::Felt252],
        gas: &mut u128,
    ) -> SyscallResult<()> {
        println!("Called `send_message_to_l1({to_address}, {payload:?})` from MLIR.");

        self.handle_syscall_request(gas, "send_message_to_l1")?;

        let addr = Address(to_address);
        self.l2_to_l1_messages.push(OrderedL2ToL1Message::new(
            self.tx_execution_context.n_sent_messages,
            addr,
            payload.to_vec(),
        ));

        // Update messages count.
        self.tx_execution_context.n_sent_messages += 1;

        Ok(())
    }

    fn keccak(
        &mut self,
        input: &[u64],
        gas: &mut u128,
    ) -> SyscallResult<cairo_native::starknet::U256> {
        println!("Called `keccak({input:?})` from MLIR.");

        self.handle_syscall_request(gas, "keccak")?;

        Ok(U256(Felt252::from(1234567890).to_le_bytes()))
    }

    fn secp256k1_add(
        &mut self,
        _p0: cairo_native::starknet::Secp256k1Point,
        _p1: cairo_native::starknet::Secp256k1Point,
        _gas: &mut u128,
    ) -> SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!()
    }

    fn secp256k1_get_point_from_x(
        &self,
        _x: cairo_native::starknet::U256,
        _y_parity: bool,
        _gas: &mut u128,
    ) -> SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!()
    }

    fn secp256k1_get_xy(
        &self,
        _p: cairo_native::starknet::Secp256k1Point,
        _gas: &mut u128,
    ) -> SyscallResult<(cairo_native::starknet::U256, cairo_native::starknet::U256)> {
        todo!()
    }

    fn secp256k1_mul(
        &self,
        _p: cairo_native::starknet::Secp256k1Point,
        _m: cairo_native::starknet::U256,
        _gas: &mut u128,
    ) -> SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!()
    }

    fn secp256k1_new(
        &self,
        _x: cairo_native::starknet::U256,
        _y: cairo_native::starknet::U256,
        _gas: &mut u128,
    ) -> SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!()
    }

    fn secp256r1_add(
        &self,
        _p0: cairo_native::starknet::Secp256k1Point,
        _p1: cairo_native::starknet::Secp256k1Point,
        _gas: &mut u128,
    ) -> SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!()
    }

    fn secp256r1_get_point_from_x(
        &self,
        _x: cairo_native::starknet::U256,
        _y_parity: bool,
        _gas: &mut u128,
    ) -> SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!()
    }

    fn secp256r1_get_xy(
        &self,
        _p: cairo_native::starknet::Secp256k1Point,
        _gas: &mut u128,
    ) -> SyscallResult<(cairo_native::starknet::U256, cairo_native::starknet::U256)> {
        todo!()
    }

    fn secp256r1_mul(
        &self,
        _p: cairo_native::starknet::Secp256k1Point,
        _m: cairo_native::starknet::U256,
        _gas: &mut u128,
    ) -> SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!()
    }

    fn secp256r1_new(
        &mut self,
        _x: cairo_native::starknet::U256,
        _y: cairo_native::starknet::U256,
        _gas: &mut u128,
    ) -> SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!()
    }

    fn pop_log(&mut self) {
        todo!()
    }

    fn set_account_contract_address(&mut self, contract_address: cairo_vm::felt::Felt252) {
        self.tx_execution_context.account_contract_address = Address(contract_address);
    }

    fn set_block_number(&mut self, block_number: u64) {
        self.block_context.block_info.block_number = block_number;
    }

    fn set_block_timestamp(&mut self, block_timestamp: u64) {
        self.block_context.block_info.block_timestamp = block_timestamp;
    }

    fn set_caller_address(&mut self, address: cairo_vm::felt::Felt252) {
        self.caller_address = Address(address);
    }

    fn set_chain_id(&mut self, chain_id: cairo_vm::felt::Felt252) {
        self.block_context.starknet_os_config.chain_id = chain_id;
    }

    fn set_contract_address(&mut self, address: cairo_vm::felt::Felt252) {
        self.contract_address = Address(address);
    }

    fn set_max_fee(&mut self, max_fee: u128) {
        self.tx_execution_context.max_fee = max_fee;
    }

    fn set_nonce(&mut self, nonce: cairo_vm::felt::Felt252) {
        self.tx_execution_context.nonce = nonce;
    }

    fn set_sequencer_address(&mut self, _address: cairo_vm::felt::Felt252) {
        todo!()
    }

    fn set_signature(&mut self, signature: &[cairo_vm::felt::Felt252]) {
        self.tx_execution_context.signature = signature.to_vec();
    }

    fn set_transaction_hash(&mut self, transaction_hash: cairo_vm::felt::Felt252) {
        self.tx_execution_context.transaction_hash = transaction_hash;
    }

    fn set_version(&mut self, version: cairo_vm::felt::Felt252) {
        self.tx_execution_context.version = version;
    }
}

impl<'a, S> NativeSyscallHandler<'a, S>
where
    S: StateReader,
{
    fn execute_constructor_entry_point(
        &mut self,
        contract_address: &Address,
        class_hash_bytes: ClassHash,
        constructor_calldata: Vec<Felt252>,
        remaining_gas: u128,
    ) -> Result<CallResult, StateError> {
        let compiled_class = if let Ok(compiled_class) = self
            .starknet_storage_state
            .state
            .get_contract_class(&class_hash_bytes)
        {
            compiled_class
        } else {
            return Ok(CallResult {
                gas_consumed: 0,
                is_success: false,
                retdata: vec![Felt252::from_bytes_be(b"CLASS_HASH_NOT_FOUND").into()],
            });
        };

        if self.constructor_entry_points_empty(compiled_class)? {
            if !constructor_calldata.is_empty() {
                return Err(StateError::ConstructorCalldataEmpty());
            }

            let call_info = CallInfo::empty_constructor_call(
                contract_address.clone(),
                self.contract_address.clone(),
                Some(class_hash_bytes),
            );
            self.internal_calls.push(call_info.clone());

            return Ok(call_info.result());
        }

        let call = ExecutionEntryPoint::new(
            contract_address.clone(),
            constructor_calldata,
            CONSTRUCTOR_ENTRY_POINT_SELECTOR.clone(),
            self.contract_address.clone(),
            EntryPointType::Constructor,
            Some(CallType::Call),
            None,
            remaining_gas,
        );

        let ExecutionResult { call_info, .. } = call
            .execute(
                self.starknet_storage_state.state,
                &self.block_context,
                &mut self.resources_manager,
                &mut self.tx_execution_context,
                false,
                u64::MAX,
            )
            .map_err(|_| StateError::ExecutionEntryPoint())?;

        let call_info = call_info.ok_or(StateError::CustomError("Execution error".to_string()))?;

        self.internal_calls.push(call_info.clone());

        Ok(call_info.result())
    }

    fn constructor_entry_points_empty(
        &self,
        contract_class: CompiledClass,
    ) -> Result<bool, StateError> {
        match contract_class {
            CompiledClass::Deprecated(class) => Ok(class
                .entry_points_by_type
                .get(&EntryPointType::Constructor)
                .ok_or(ContractClassError::NoneEntryPointType)?
                .is_empty()),
            CompiledClass::Casm(class) => Ok(class.entry_points_by_type.constructor.is_empty()),
            CompiledClass::Sierra(class) => Ok(class.entry_points_by_type.constructor.is_empty()),
        }
    }
}
