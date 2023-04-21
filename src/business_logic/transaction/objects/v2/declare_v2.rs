use std::collections::HashMap;

use crate::{
    business_logic::{
        execution::{
            execution_entry_point::ExecutionEntryPoint,
            objects::{CallInfo, CallType, TransactionExecutionContext, TransactionExecutionInfo},
        },
        fact_state::state::ExecutionResourcesManager,
        state::state_api::{State, StateReader},
        transaction::{
            error::TransactionError,
            fee::{calculate_tx_fee, execute_fee_transfer, FeeInfo},
            objects::internal_invoke_function::verify_no_calls_to_other_contracts,
        },
    },
    core::transaction_hash::starknet_transaction_hash::calculate_declare_v2_transaction_hash,
    definitions::{
        constants::VALIDATE_DECLARE_ENTRY_POINT_SELECTOR, general_config::StarknetGeneralConfig,
        transaction_type::TransactionType,
    },
    services::api::contract_classes::deprecated_contract_class::EntryPointType,
    utils::{calculate_tx_resources, Address},
};
use cairo_lang_starknet::contract_class::ContractClass as SierraContractClass;
use felt::Felt252;
use num_traits::Zero;
#[derive(Debug)]
pub struct InternalDeclareV2 {
    pub sender_address: Address,
    pub tx_type: TransactionType,
    pub validate_entry_point_selector: Felt252,
    pub version: u64,
    pub max_fee: u64,
    pub signature: Vec<Felt252>,
    pub nonce: Felt252,
    pub compiled_class_hash: Felt252,
    pub sierra_contract_class: SierraContractClass,
    pub hash_value: Felt252,
}

impl InternalDeclareV2 {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        sierra_contract_class: &SierraContractClass,
        compiled_class_hash: Felt252,
        chain_id: Felt252,
        sender_address: Address,
        max_fee: u64,
        version: u64,
        signature: Vec<Felt252>,
        nonce: Felt252,
    ) -> Result<Self, TransactionError> {
        let validate_entry_point_selector = VALIDATE_DECLARE_ENTRY_POINT_SELECTOR.clone();

        let hash_value = calculate_declare_v2_transaction_hash(
            sierra_contract_class,
            compiled_class_hash.clone(),
            chain_id,
            &sender_address,
            max_fee,
            version,
            nonce.clone(),
        )?;

        let internal_declare = InternalDeclareV2 {
            sierra_contract_class: sierra_contract_class.to_owned(),
            sender_address,
            tx_type: TransactionType::Declare,
            validate_entry_point_selector,
            version,
            max_fee,
            signature,
            nonce,
            compiled_class_hash,
            hash_value,
        };

        internal_declare.verify_version()?;

        Ok(internal_declare)
    }

    pub fn verify_version(&self) -> Result<(), TransactionError> {
        if self.version.is_zero() {
            if !self.max_fee.is_zero() {
                return Err(TransactionError::StarknetError(
                    "The max_fee field in Declare transactions of version 0 must be 0.".to_string(),
                ));
            }

            if !self.nonce.is_zero() {
                return Err(TransactionError::StarknetError(
                    "The nonce field in Declare transactions of version 0 must be 0.".to_string(),
                ));
            }
        }

        if !self.signature.len().is_zero() {
            return Err(TransactionError::StarknetError(
                "The signature field in Declare transactions must be an empty list.".to_string(),
            ));
        }
        Ok(())
    }

    /// Executes a call to the cairo-vm using the accounts_validation.cairo contract to validate
    /// the contract that is being declared. Then it returns the transaction execution info of the run.
    // pub fn apply<S: Default + State + StateReader + Clone>(
    //     &self,
    //     state: &mut S,
    //     general_config: &StarknetGeneralConfig,
    // ) -> Result<TransactionExecutionInfo, TransactionError> {
    //     self.verify_version()?;

    //     // validate transaction
    //     let mut resources_manager = ExecutionResourcesManager::default();
    //     let validate_info =
    //         self.run_validate_entrypoint(state, &mut resources_manager, general_config)?;

    //     let class_hash = compute_sierra_class_hash(&self.sierra_contract_class)?;

    //     if class_hash != self.compiled_class_hash {
    //         return Err(TransactionError::NotEqualClassHash);
    //     }

    //     let changes = state.count_actual_storage_changes();
    //     let actual_resources = calculate_tx_resources(
    //         resources_manager,
    //         &[Some(validate_info.clone())],
    //         TransactionType::Declare,
    //         changes,
    //         None,
    //     )
    //     .map_err(|_| TransactionError::ResourcesCalculation)?;

    //     Ok(
    //         TransactionExecutionInfo::create_concurrent_stage_execution_info(
    //             validate_info,
    //             None,
    //             actual_resources,
    //             Some(self.tx_type),
    //         ),
    //     )
    // }

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Internal Account Functions
    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~
    pub fn get_execution_context(&self, n_steps: u64) -> TransactionExecutionContext {
        TransactionExecutionContext::new(
            self.sender_address.clone(),
            self.hash_value.clone(),
            self.signature.clone(),
            self.max_fee,
            self.nonce.clone(),
            n_steps,
            self.version,
        )
    }

    pub fn get_calldata(&self) -> Vec<Felt252> {
        let bytes = self.compiled_class_hash.clone();
        Vec::from([bytes])
    }

    /// Calculates and charges the actual fee.
    pub fn charge_fee<S: Default + State + StateReader + Clone>(
        &self,
        state: &mut S,
        resources: &HashMap<String, usize>,
        general_config: &StarknetGeneralConfig,
    ) -> Result<FeeInfo, TransactionError> {
        if self.max_fee.is_zero() {
            return Ok((None, 0));
        }

        let actual_fee = calculate_tx_fee(
            resources,
            general_config.starknet_os_config.gas_price,
            general_config,
        )?;

        let tx_context = self.get_execution_context(general_config.invoke_tx_max_n_steps);
        let fee_transfer_info =
            execute_fee_transfer(state, general_config, &tx_context, actual_fee)?;

        Ok((Some(fee_transfer_info), actual_fee))
    }

    // TODO: delete once used
    #[allow(dead_code)]
    fn handle_nonce<S: Default + State + StateReader + Clone>(
        &self,
        state: &mut S,
    ) -> Result<(), TransactionError> {
        if self.version == 0 {
            return Ok(());
        }

        let contract_address = &self.sender_address;
        let current_nonce = state.get_nonce_at(contract_address)?.to_owned();
        if current_nonce != self.nonce {
            return Err(TransactionError::InvalidTransactionNonce(
                current_nonce.to_string(),
                self.nonce.to_string(),
            ));
        }

        state.increment_nonce(contract_address)?;

        Ok(())
    }

    pub fn execute<S: Default + State + StateReader + Clone>(
        &self,
        state: &mut S,
        general_config: &StarknetGeneralConfig,
        remaining_gas: u64,
    ) -> Result<TransactionExecutionInfo, TransactionError> {
        self.verify_version()?;

        let mut resources_manager = ExecutionResourcesManager::default();
        let (validate_info, _remaining_gas) = self.run_validate_entrypoint(
            remaining_gas,
            state,
            &mut resources_manager,
            general_config,
        )?;

        let storage_changes = state.count_actual_storage_changes();

        let actual_resources = calculate_tx_resources(
            resources_manager,
            &[Some(validate_info.clone())],
            self.tx_type,
            storage_changes,
            None,
        )?;

        Ok(
            TransactionExecutionInfo::create_concurrent_stage_execution_info(
                Some(validate_info),
                None,
                actual_resources,
                Some(self.tx_type),
            ),
        )
    }

    fn run_validate_entrypoint<S: Default + State + StateReader + Clone>(
        &self,
        mut remaining_gas: u64,
        state: &mut S,
        resources_manager: &mut ExecutionResourcesManager,
        general_config: &StarknetGeneralConfig,
    ) -> Result<(CallInfo, u64), TransactionError> {
        let calldata = [self.compiled_class_hash.clone()].to_vec();

        let entry_point = ExecutionEntryPoint {
            contract_address: self.sender_address.clone(),
            entry_point_selector: self.validate_entry_point_selector.clone(),
            initial_gas: remaining_gas,
            entry_point_type: EntryPointType::External,
            calldata,
            caller_address: Address(Felt252::zero()),
            code_address: None,
            class_hash: None,
            call_type: CallType::Call,
        };

        let tx_execution_context = self.get_execution_context(general_config.validate_max_n_steps);

        let call_info = entry_point.execute(
            state,
            general_config,
            resources_manager,
            &tx_execution_context,
        )?;

        let class_hash = state.get_class_hash_at(&self.sender_address)?.clone();
        let _compiled_class_hash = state.get_compiled_class_hash(&class_hash)?;

        remaining_gas -= call_info.gas_consumed;
        verify_no_calls_to_other_contracts(&call_info)?;

        Ok((call_info, remaining_gas))
    }
}

// TODO: uncomment this tests moduloe once the sierra compiler is fully functional

// #[cfg(test)]
// mod tests {
//     use std::{fs::File, io::BufReader, path::PathBuf};

//     use super::InternalDeclareV2;
//     use crate::{definitions::general_config::StarknetChainId, utils::Address};
//     use felt::Felt252;
//     use num_traits::Zero;

//     #[test]
//     fn create_declare_v2_test() {
//         let path = PathBuf::from("starknet_programs/test_sierra.json");
//         let file = File::open(path).unwrap();
//         let reader = BufReader::new(file);
//         let sierra_contract_class: cairo_lang_starknet::contract_class::ContractClass =
//             serde_json::from_reader(reader).unwrap();
//         let chain_id = StarknetChainId::TestNet.to_felt();

//         let sender_address = Address(0.into());

//         let internal_declare = InternalDeclareV2::new(
//             &sierra_contract_class,
//             Felt252::zero(),
//             chain_id,
//             sender_address,
//             0,
//             0,
//             [].to_vec(),
//             Felt252::zero(),
//         );

//         assert!(internal_declare.is_ok());
//     }
// }
