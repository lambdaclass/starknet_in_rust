use crate::VersionSpecificAccountTxFields;
use crate::{
    core::errors::state_errors::StateError,
    definitions::{block_context::BlockContext, constants::CONSTRUCTOR_ENTRY_POINT_SELECTOR},
    execution::{
        execution_entry_point::{ExecutionEntryPoint, ExecutionResult},
        CallInfo, CallResult, CallType, OrderedEvent, OrderedL2ToL1Message,
        TransactionExecutionContext,
    },
    hash_utils::calculate_contract_address,
    sandboxing::IsolatedExecutor,
    services::api::{
        contract_class_errors::ContractClassError, contract_classes::compiled_class::CompiledClass,
    },
    state::{
        contract_storage_state::ContractStorageState,
        state_api::{State, StateReader},
        ExecutionResourcesManager,
    },
    syscalls::{
        business_logic_syscall_handler::{KECCAK_ROUND_COST, SYSCALL_BASE, SYSCALL_GAS_COST},
        syscall_handler_errors::SyscallHandlerError,
    },
    transaction::{error::TransactionError, Address},
    utils::{felt_to_hash, ClassHash},
    ContractClassCache, EntryPointType,
};
use cairo_native::starknet::{ExecutionInfoV2, ResourceBounds, TxV2Info};
use cairo_native::{
    cache::ProgramCache,
    starknet::{BlockInfo, ExecutionInfo, StarkNetSyscallHandler, SyscallResult, TxInfo, U256},
};
use cairo_vm::Felt252;
use starknet::core::utils::cairo_short_string_to_felt;
use std::{cell::RefCell, rc::Rc};

#[derive(Debug)]
pub struct NativeSyscallHandler<'a, 'cache, S, C>
where
    S: StateReader,
    C: ContractClassCache,
{
    pub(crate) starknet_storage_state: ContractStorageState<'a, S, C>,
    pub(crate) contract_address: Address,
    pub(crate) caller_address: Address,
    pub(crate) entry_point_selector: Felt252,
    pub(crate) events: Vec<OrderedEvent>,
    pub(crate) l2_to_l1_messages: Vec<OrderedL2ToL1Message>,
    pub(crate) resources_manager: ExecutionResourcesManager,
    pub(crate) tx_execution_context: TransactionExecutionContext,
    pub(crate) block_context: BlockContext,
    pub(crate) internal_calls: Vec<CallInfo>,
    pub(crate) program_cache: Rc<RefCell<ProgramCache<'cache, ClassHash>>>,
    pub(crate) sandbox: Option<&'a IsolatedExecutor>,
}

impl<'a, 'cache, S: StateReader, C: ContractClassCache> NativeSyscallHandler<'a, 'cache, S, C> {
    /// Generic code that needs to be run on all syscalls.
    fn handle_syscall_request(&mut self, gas: &mut u128, syscall_name: &str) -> SyscallResult<()> {
        let required_gas = SYSCALL_GAS_COST
            .get(syscall_name)
            .map(|&x| x.saturating_sub(SYSCALL_BASE))
            .unwrap_or(0);

        if *gas < required_gas {
            let out_of_gas_felt = Felt252::from_bytes_be_slice("Out of gas".as_bytes());
            tracing::debug!("out of gas!: {:?} < {:?}", *gas, required_gas);
            return Err(vec![out_of_gas_felt]);
        }

        *gas = gas.saturating_sub(required_gas);

        self.resources_manager
            .increment_syscall_counter(syscall_name, 1);

        Ok(())
    }
}
impl<'a, 'cache, S: StateReader, C: ContractClassCache> StarkNetSyscallHandler
    for NativeSyscallHandler<'a, 'cache, S, C>
{
    fn get_block_hash(
        &mut self,
        block_number: u64,
        gas: &mut u128,
    ) -> SyscallResult<cairo_vm::Felt252> {
        tracing::debug!("Called `get_block_hash({block_number})` from Cairo Native");
        self.handle_syscall_request(gas, "get_block_hash")?;

        let current_block_number = self.block_context.block_info.block_number;

        if current_block_number < 10 || block_number > current_block_number - 10 {
            let out_of_range_felt =
                Felt252::from_bytes_be_slice("Block number out of range".as_bytes());
            return Err(vec![out_of_range_felt]);
        }
        let key: Felt252 = block_number.into();
        let block_hash_address = Address(1.into());

        match self
            .starknet_storage_state
            .state
            .get_storage_at(&(block_hash_address, key.to_bytes_be()))
        {
            Ok(value) => Ok(value),
            Err(e) => Err(vec![Felt252::from_bytes_be_slice(e.to_string().as_bytes())]),
        }
    }

    fn get_execution_info(
        &mut self,
        gas: &mut u128,
    ) -> SyscallResult<cairo_native::starknet::ExecutionInfo> {
        tracing::debug!("Called `get_execution_info()` from Cairo Native");

        self.handle_syscall_request(gas, "get_execution_info")?;

        Ok(ExecutionInfo {
            block_info: BlockInfo {
                block_number: self.block_context.block_info.block_number,
                block_timestamp: self.block_context.block_info.block_timestamp,
                sequencer_address: self.block_context.block_info.sequencer_address.0,
            },
            tx_info: TxInfo {
                version: self.tx_execution_context.version,
                account_contract_address: self.tx_execution_context.account_contract_address.0,
                max_fee: self
                    .tx_execution_context
                    .account_tx_fields
                    .max_fee_for_execution_info(),
                signature: self.tx_execution_context.signature.clone(),
                transaction_hash: self.tx_execution_context.transaction_hash,
                chain_id: self.block_context.starknet_os_config.chain_id,
                nonce: self.tx_execution_context.nonce,
            },
            caller_address: self.caller_address.0,
            contract_address: self.contract_address.0,
            entry_point_selector: self.entry_point_selector,
        })
    }

    fn deploy(
        &mut self,
        class_hash: Felt252,
        contract_address_salt: Felt252,
        calldata: &[Felt252],
        deploy_from_zero: bool,
        gas: &mut u128,
    ) -> SyscallResult<(Felt252, Vec<Felt252>)> {
        tracing::debug!("Called `deploy({class_hash}, {calldata:?})` from Cairo Native");
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
                vec![Felt252::from_bytes_be_slice(
                    b"FAILED_TO_CALCULATE_CONTRACT_ADDRESS",
                )]
            })?,
        );
        // Initialize the contract.
        let class_hash_bytes: ClassHash = felt_to_hash(&class_hash);

        self.starknet_storage_state
            .state
            .deploy_contract(contract_address.clone(), class_hash_bytes)
            .map_err(|_| {
                vec![Felt252::from_bytes_be_slice(
                    b"CONTRACT_ADDRESS_UNAVAILABLE",
                )]
            })?;

        let result = self
            .execute_constructor_entry_point(
                &contract_address,
                class_hash_bytes,
                calldata.to_vec(),
                *gas,
            )
            .map_err(|_| {
                vec![Felt252::from_bytes_be_slice(
                    b"CONSTRUCTOR_ENTRYPOINT_FAILURE",
                )]
            })?;

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

    fn replace_class(&mut self, class_hash: Felt252, gas: &mut u128) -> SyscallResult<()> {
        tracing::debug!("Called `replace_class({class_hash})` from Cairo Native");

        self.handle_syscall_request(gas, "replace_class")?;
        match self
            .starknet_storage_state
            .state
            .set_class_hash_at(self.contract_address.clone(), ClassHash::from(class_hash))
        {
            Ok(_) => Ok(()),
            Err(e) => {
                let replace_class_felt = Felt252::from_bytes_be_slice(e.to_string().as_bytes());
                Err(vec![replace_class_felt])
            }
        }
    }

    fn library_call(
        &mut self,
        class_hash: Felt252,
        function_selector: Felt252,
        calldata: &[Felt252],
        gas: &mut u128,
    ) -> SyscallResult<Vec<Felt252>> {
        tracing::debug!(
            "Called `library_call({class_hash}, {function_selector}, {calldata:?})` from Cairo Native"
        );

        self.handle_syscall_request(gas, "library_call")?;

        let execution_entry_point = ExecutionEntryPoint::new(
            self.contract_address.clone(),
            calldata.to_vec(),
            function_selector,
            self.caller_address.clone(),
            EntryPointType::External,
            Some(CallType::Delegate),
            Some(ClassHash::from(class_hash)),
            *gas,
        );

        let ExecutionResult {
            call_info,
            revert_error,
            ..
        } = execution_entry_point.execute(
            self.starknet_storage_state.state,
            &self.block_context,
            &mut self.resources_manager,
            &mut self.tx_execution_context,
            false,
            self.block_context.invoke_tx_max_n_steps,
            Some(self.program_cache.clone()),
            self.sandbox,
        )?;

        let call_info = call_info.ok_or(SyscallHandlerError::ExecutionError(
            revert_error.unwrap_or_else(|| "Execution error".to_string()),
        ))?;

        let remaining_gas = gas.saturating_sub(call_info.gas_consumed);
        *gas = remaining_gas;

        let failure_flag = call_info.failure_flag;
        let retdata = call_info.retdata.clone();

        self.starknet_storage_state
            .read_values
            .extend(call_info.storage_read_values.clone());
        self.starknet_storage_state
            .accessed_keys
            .extend(call_info.accessed_storage_keys.clone());

        self.internal_calls.push(call_info);

        if failure_flag {
            Err(retdata)
        } else {
            Ok(retdata)
        }
    }

    fn call_contract(
        &mut self,
        address: Felt252,
        entrypoint_selector: Felt252,
        calldata: &[Felt252],
        gas: &mut u128,
    ) -> SyscallResult<Vec<Felt252>> {
        tracing::debug!(
            "Called `call_contract({address}, {entrypoint_selector}, {calldata:?})` from Cairo Native"
        );

        self.handle_syscall_request(gas, "call_contract")?;

        let address = Address(address);
        let exec_entry_point = ExecutionEntryPoint::new(
            address,
            calldata.to_vec(),
            entrypoint_selector,
            self.contract_address.clone(),
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
                Some(self.program_cache.clone()),
                self.sandbox,
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
        address: Felt252,
        gas: &mut u128,
    ) -> SyscallResult<Felt252> {
        tracing::debug!("Called `storage_read({address_domain}, {address})` from Cairo Native");
        self.handle_syscall_request(gas, "storage_read")?;
        let value = match self.starknet_storage_state.read(Address(address)) {
            Ok(value) => Ok(value),
            Err(_e @ StateError::Io(_)) => todo!(),
            Err(_) => Ok(Felt252::ZERO),
        };

        tracing::debug!(
            "Called `storage_read({address_domain}, {address}) = {value:?}` from Cairo Native"
        );
        value
    }

    fn storage_write(
        &mut self,
        address_domain: u32,
        address: Felt252,
        value: Felt252,
        gas: &mut u128,
    ) -> SyscallResult<()> {
        tracing::debug!(
            "Called `storage_write({address_domain}, {address}, {value})` from Cairo Native"
        );

        self.handle_syscall_request(gas, "storage_write")?;
        self.starknet_storage_state.write(Address(address), value);
        Ok(())
    }

    fn emit_event(
        &mut self,
        keys: &[Felt252],
        data: &[Felt252],
        gas: &mut u128,
    ) -> SyscallResult<()> {
        let order = self.tx_execution_context.n_emitted_events;
        tracing::debug!("Called `emit_event(KEYS: {keys:?}, DATA: {data:?})` from Cairo Native");

        self.handle_syscall_request(gas, "emit_event")?;

        self.events
            .push(OrderedEvent::new(order, keys.to_vec(), data.to_vec()));
        self.tx_execution_context.n_emitted_events += 1;
        Ok(())
    }

    fn send_message_to_l1(
        &mut self,
        to_address: Felt252,
        payload: &[Felt252],
        gas: &mut u128,
    ) -> SyscallResult<()> {
        tracing::debug!("Called `send_message_to_l1({to_address}, {payload:?})` from Cairo Native");

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
        tracing::debug!("Called `keccak({input:?})` from Cairo Native");

        self.handle_syscall_request(gas, "keccak")?;

        let length = input.len();

        if length % 17 != 0 {
            let error_msg = b"Invalid keccak input size";
            let felt_error = Felt252::from_bytes_be_slice(error_msg);
            return Err(vec![felt_error]);
        }

        let n_chunks = length / 17;
        let mut state = [0u64; 25];

        for i in 0..n_chunks {
            if *gas < KECCAK_ROUND_COST {
                let error_msg = b"Syscall out of gas";
                let felt_error = Felt252::from_bytes_be_slice(error_msg);
                return Err(vec![felt_error]);
            }
            *gas -= KECCAK_ROUND_COST;
            let chunk = &input[i * 17..(i + 1) * 17]; //(request.input_start + i * 17)?;
            for (i, val) in chunk.iter().enumerate() {
                state[i] ^= val;
            }
            keccak::f1600(&mut state)
        }
        // state[0] and state[1] conform the hash_high (u128)
        // state[2] and state[3] conform the hash_low (u128)

        SyscallResult::Ok(U256 {
            lo: state[2] as u128 | ((state[3] as u128) << 64),
            hi: state[0] as u128 | ((state[1] as u128) << 64),
        })
    }

    fn get_execution_info_v2(
        &mut self,
        gas: &mut u128,
    ) -> Result<ExecutionInfoV2, Vec<cairo_vm::Felt252>> {
        tracing::debug!("Called `get_execution_info_v2()` from Cairo Native");

        self.handle_syscall_request(gas, "get_execution_info")?;

        lazy_static::lazy_static! {
            static ref L1_GAS: Felt252 = Felt252::from_hex(
                "0x00000000000000000000000000000000000000000000000000004c315f474153"
            )
            .unwrap();
            static ref L2_GAS: Felt252 = Felt252::from_hex(
                "0x00000000000000000000000000000000000000000000000000004c325f474153"
            )
            .unwrap();
        }

        let mut resource_bounds = vec![];
        let mut tip = 0;
        let mut paymaster_data = vec![];
        let mut nonce_data_availability_mode: u32 = 0;
        let mut fee_data_availability_mode: u32 = 0;
        let mut account_deployment_data = vec![];
        if let VersionSpecificAccountTxFields::Current(fields) =
            &self.tx_execution_context.account_tx_fields
        {
            resource_bounds.push(ResourceBounds {
                resource: *L1_GAS,
                max_amount: fields.l1_resource_bounds.max_amount,
                max_price_per_unit: fields.l1_resource_bounds.max_price_per_unit,
            });
            if let Some(bounds) = &fields.l2_resource_bounds {
                resource_bounds.push(ResourceBounds {
                    resource: *L2_GAS,
                    max_amount: bounds.max_amount,
                    max_price_per_unit: bounds.max_price_per_unit,
                });
            }
            tip = fields.tip as u128;
            paymaster_data = fields.paymaster_data.clone();
            account_deployment_data = fields.account_deployment_data.clone();
            nonce_data_availability_mode = fields.nonce_data_availability_mode.into();
            fee_data_availability_mode = fields.fee_data_availability_mode.into();
        }

        Ok(ExecutionInfoV2 {
            block_info: BlockInfo {
                block_number: self.block_context.block_info.block_number,
                block_timestamp: self.block_context.block_info.block_timestamp,
                sequencer_address: self.block_context.block_info.sequencer_address.0,
            },
            tx_info: TxV2Info {
                version: self.tx_execution_context.version,
                account_contract_address: self.tx_execution_context.account_contract_address.0,
                max_fee: self
                    .tx_execution_context
                    .account_tx_fields
                    .max_fee_for_execution_info(),
                signature: self.tx_execution_context.signature.clone(),
                transaction_hash: self.tx_execution_context.transaction_hash,
                chain_id: self.block_context.starknet_os_config.chain_id,
                nonce: self.tx_execution_context.nonce,
                resource_bounds,
                tip,
                paymaster_data,
                nonce_data_availability_mode,
                fee_data_availability_mode,
                account_deployment_data,
            },
            caller_address: self.caller_address.0,
            contract_address: self.contract_address.0,
            entry_point_selector: self.entry_point_selector,
        })
    }

    fn secp256k1_add(
        &mut self,
        _p0: cairo_native::starknet::Secp256k1Point,
        _p1: cairo_native::starknet::Secp256k1Point,
        _remaining_gas: &mut u128,
    ) -> SyscallResult<cairo_native::starknet::Secp256k1Point> {
        todo!()
    }

    fn secp256k1_get_point_from_x(
        &mut self,
        _x: cairo_native::starknet::U256,
        _y_parity: bool,
        _gas: &mut u128,
    ) -> SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!()
    }

    fn secp256k1_get_xy(
        &mut self,
        _p: cairo_native::starknet::Secp256k1Point,
        _gas: &mut u128,
    ) -> SyscallResult<(cairo_native::starknet::U256, cairo_native::starknet::U256)> {
        todo!()
    }

    fn secp256k1_mul(
        &mut self,
        _p: cairo_native::starknet::Secp256k1Point,
        _m: U256,
        _remaining_gas: &mut u128,
    ) -> SyscallResult<cairo_native::starknet::Secp256k1Point> {
        todo!()
    }

    fn secp256k1_new(
        &mut self,
        _x: cairo_native::starknet::U256,
        _y: cairo_native::starknet::U256,
        _gas: &mut u128,
    ) -> SyscallResult<Option<cairo_native::starknet::Secp256k1Point>> {
        todo!()
    }

    fn secp256r1_add(
        &mut self,
        _p0: cairo_native::starknet::Secp256r1Point,
        _p1: cairo_native::starknet::Secp256r1Point,
        _remaining_gas: &mut u128,
    ) -> SyscallResult<cairo_native::starknet::Secp256r1Point> {
        todo!()
    }

    fn secp256r1_get_point_from_x(
        &mut self,
        _x: U256,
        _y_parity: bool,
        _remaining_gas: &mut u128,
    ) -> SyscallResult<Option<cairo_native::starknet::Secp256r1Point>> {
        todo!()
    }

    fn secp256r1_get_xy(
        &mut self,
        _p: cairo_native::starknet::Secp256r1Point,
        _remaining_gas: &mut u128,
    ) -> SyscallResult<(U256, U256)> {
        todo!()
    }

    fn secp256r1_mul(
        &mut self,
        _p: cairo_native::starknet::Secp256r1Point,
        _m: U256,
        _remaining_gas: &mut u128,
    ) -> SyscallResult<cairo_native::starknet::Secp256r1Point> {
        todo!()
    }

    fn secp256r1_new(
        &mut self,
        _x: U256,
        _y: U256,
        _remaining_gas: &mut u128,
    ) -> SyscallResult<Option<cairo_native::starknet::Secp256r1Point>> {
        todo!()
    }

    fn pop_log(&mut self) {
        todo!()
    }

    fn set_account_contract_address(&mut self, contract_address: Felt252) {
        self.tx_execution_context.account_contract_address = Address(contract_address);
    }

    fn set_block_number(&mut self, block_number: u64) {
        self.block_context.block_info.block_number = block_number;
    }

    fn set_block_timestamp(&mut self, block_timestamp: u64) {
        self.block_context.block_info.block_timestamp = block_timestamp;
    }

    fn set_caller_address(&mut self, address: Felt252) {
        self.caller_address = Address(address);
    }

    fn set_chain_id(&mut self, chain_id: Felt252) {
        self.block_context.starknet_os_config.chain_id = chain_id;
    }

    fn set_contract_address(&mut self, address: Felt252) {
        self.contract_address = Address(address);
    }

    fn set_max_fee(&mut self, max_fee: u128) {
        if matches!(
            self.tx_execution_context.account_tx_fields,
            VersionSpecificAccountTxFields::Deprecated(_)
        ) {
            self.tx_execution_context.account_tx_fields =
                VersionSpecificAccountTxFields::new_deprecated(max_fee)
        };
    }

    fn set_nonce(&mut self, nonce: Felt252) {
        self.tx_execution_context.nonce = nonce;
    }

    fn set_sequencer_address(&mut self, _address: Felt252) {
        todo!()
    }

    fn set_signature(&mut self, signature: &[Felt252]) {
        self.tx_execution_context.signature = signature.to_vec();
    }

    fn set_transaction_hash(&mut self, transaction_hash: Felt252) {
        self.tx_execution_context.transaction_hash = transaction_hash;
    }

    fn set_version(&mut self, version: Felt252) {
        self.tx_execution_context.version = version;
    }
}

impl<'a, 'cache, S, C> NativeSyscallHandler<'a, 'cache, S, C>
where
    S: StateReader,
    C: ContractClassCache,
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
                retdata: vec![Felt252::from_bytes_be_slice(b"CLASS_HASH_NOT_FOUND").into()],
            });
        };

        if self.constructor_entry_points_empty(compiled_class)? {
            if !constructor_calldata.is_empty() {
                return Err(StateError::ConstructorCalldataEmpty);
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
            *CONSTRUCTOR_ENTRY_POINT_SELECTOR,
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
                Some(self.program_cache.clone()),
                self.sandbox,
            )
            .map_err(|_| StateError::ExecutionEntryPoint)?;

        let call_info = call_info.ok_or(StateError::CustomError("Execution error".to_string()))?;

        self.internal_calls.push(call_info.clone());

        Ok(call_info.result())
    }

    fn constructor_entry_points_empty(
        &self,
        contract_class: CompiledClass,
    ) -> Result<bool, StateError> {
        Ok(match contract_class {
            CompiledClass::Deprecated(class) => class
                .entry_points_by_type
                .get(&EntryPointType::Constructor)
                .ok_or(ContractClassError::NoneEntryPointType)?
                .is_empty(),
            CompiledClass::Casm { casm: class, .. } => {
                class.entry_points_by_type.constructor.is_empty()
            }
        })
    }
}

impl From<TransactionError> for Vec<Felt252> {
    fn from(value: TransactionError) -> Self {
        #[inline]
        fn str_to_felt(x: &str) -> Felt252 {
            let felt = cairo_short_string_to_felt(x).expect("shouldnt fail");
            Felt252::from_bytes_be(&felt.to_bytes_be())
        }

        let value = value.to_string();

        if value.len() < 32 {
            vec![str_to_felt(&value)]
        } else {
            let mut felts = vec![];
            let mut buffer = Vec::with_capacity(31);

            for c in value.chars() {
                buffer.push(c);

                if buffer.len() == 31 {
                    let value: String = buffer.iter().collect();
                    felts.push(str_to_felt(&value));
                    buffer.clear();
                }
            }

            if !buffer.is_empty() {
                let value: String = buffer.iter().collect();
                felts.push(str_to_felt(&value));
            }

            felts
        }
    }
}

impl From<SyscallHandlerError> for Vec<Felt252> {
    fn from(value: SyscallHandlerError) -> Self {
        #[inline]
        fn str_to_felt(x: &str) -> Felt252 {
            let felt = cairo_short_string_to_felt(x).expect("shouldnt fail");
            Felt252::from_bytes_be(&felt.to_bytes_be())
        }

        let value = value.to_string();

        if value.len() < 32 {
            vec![str_to_felt(&value)]
        } else {
            let mut felts = vec![];
            let mut buffer = Vec::with_capacity(31);

            for c in value.chars() {
                buffer.push(c);

                if buffer.len() == 31 {
                    let value: String = buffer.iter().collect();
                    felts.push(str_to_felt(&value));
                    buffer.clear();
                }
            }

            if !buffer.is_empty() {
                let value: String = buffer.iter().collect();
                felts.push(str_to_felt(&value));
            }

            felts
        }
    }
}
