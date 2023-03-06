use clap::{Args, Parser, Subcommand};
use felt::Felt;
use num_traits::{Num, Zero};
use starknet_rs::{
    business_logic::{
        execution::{
            execution_entry_point::ExecutionEntryPoint,
            objects::{CallType, TransactionExecutionContext},
        },
        fact_state::{
            contract_state::ContractState, in_memory_state_reader::InMemoryStateReader,
            state::ExecutionResourcesManager,
        },
        state::cached_state::CachedState,
    },
    core::{
        contract_address::starknet_contract_address::compute_class_hash,
        transaction_hash::starknet_transaction_hash::{
            calculate_declare_transaction_hash, calculate_deploy_transaction_hash,
            calculate_transaction_hash_common, TransactionHashPrefix,
        },
    },
    definitions::{constants::TRANSACTION_VERSION, general_config::StarknetGeneralConfig},
    hash_utils::calculate_contract_address,
    parser_errors::ParserError,
    serde_structs::contract_abi::read_abi,
    server::{
        add_address, add_class_hash, get_contract_from_address, get_contract_from_class_hash,
    },
    services::api::contract_class::ContractClass,
    utils::{felt_to_hash, Address},
};
use std::{collections::HashMap, path::PathBuf};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Declare(DeclareArgs),
    Deploy(DeployArgs),
    Invoke(InvokeArgs),
}

#[derive(Args)]
struct DeclareArgs {
    #[arg(long)]
    contract: PathBuf,
}

#[derive(Args)]
struct DeployArgs {
    #[arg(long = "class_hash")]
    class_hash: String,
    #[arg(long, default_value = "1111")]
    salt: i32,
    #[arg(long, num_args=1.., value_delimiter = ' ')]
    inputs: Option<Vec<i32>>,
}

#[derive(Args)]
struct InvokeArgs {
    #[arg(long)]
    address: String,
    #[arg(long)]
    abi: PathBuf,
    #[arg(long)]
    function: String,
    #[arg(long, num_args=1.., value_delimiter = ' ')]
    inputs: Option<Vec<i32>>,
}

fn declare_parser(args: &DeclareArgs) -> Result<(), ParserError> {
    let contract_class =
        ContractClass::try_from(&args.contract).map_err(ParserError::OpenFileError)?;
    let class_hash =
        compute_class_hash(&contract_class).map_err(ParserError::ComputeClassHashError)?;
    add_class_hash(&(&class_hash).to_biguint().to_str_radix(16), &args.contract);

    let tx_hash = calculate_declare_transaction_hash(
        contract_class,
        Felt::zero(),
        Address(Felt::zero()),
        0,
        0,
        Felt::zero(),
    )
    .map_err(ParserError::ComputeTransactionHashError)?;
    println!(
        "Declare transaction was sent.\nContract class hash: 0x{:x}\nTransaction hash: 0x{:x}",
        class_hash.to_biguint(),
        tx_hash.to_biguint()
    );
    Ok(())
}

fn deploy_parser(args: &DeployArgs) -> Result<(), ParserError> {
    let contract_name = get_contract_from_class_hash(&args.class_hash[2..].to_string());
    let constructor_calldata = match &args.inputs {
        Some(vec) => vec.iter().map(|&n| n.into()).collect(),
        None => Vec::new(),
    };
    let address = calculate_contract_address(
        &Address(args.salt.into()),
        &Felt::from_str_radix(&args.class_hash[2..], 16)
            .map_err(|_| ParserError::ParseHashError(args.class_hash.clone()))?,
        &constructor_calldata,
        Address(Felt::zero()),
    )
    .map_err(ParserError::ComputeAddressError)?;
    add_address(&address.to_str_radix(16), &contract_name);
    let tx_hash = calculate_deploy_transaction_hash(
        0,
        Address(address.clone()),
        &constructor_calldata,
        Felt::zero(),
    )
    .map_err(ParserError::ComputeTransactionHashError)?;
    println!("Invoke transaction for contract deployment was sent.\nContract address: 0x{:x}\nTransaction hash: 0x{:x}", address.to_biguint(), tx_hash.to_biguint());
    Ok(())
}

fn invoke_parser(args: &InvokeArgs) -> Result<(), ParserError> {
    let contract_name = get_contract_from_address(&args.address[2..].to_string());
    let contract_address = Felt::from_str_radix(&args.address[2..].to_string(), 16)
        .map_err(|_| ParserError::ParseHashError(args.address.clone()))?;
    let contract_class =
        ContractClass::try_from(contract_name).map_err(ParserError::OpenFileError)?;
    let class_hash =
        compute_class_hash(&contract_class).map_err(ParserError::ComputeClassHashError)?;
    let function_entrypoint_indexes = read_abi(&args.abi);

    let entry_points_by_type = contract_class.entry_points_by_type().clone();
    let (entry_point_index, entry_point_type) = function_entrypoint_indexes
        .get(&args.function)
        .ok_or(ParserError::FunctionEntryPointError(args.function.clone()))?;

    let entrypoint_selector = entry_points_by_type
        .get(entry_point_type)
        .ok_or(ParserError::EntryPointType(entry_point_type.clone()))?
        .get(*entry_point_index)
        .ok_or(ParserError::EntryPointIndex(entry_point_index.clone()))?
        .selector()
        .clone();

    let contract_state = ContractState::new(felt_to_hash(&class_hash), 0.into(), HashMap::new());

    let mut state_reader = InMemoryStateReader::new(HashMap::new(), HashMap::new());
    state_reader
        .contract_states_mut()
        .insert(Address(contract_address.clone()), contract_state);

    let mut state = CachedState::new(
        state_reader,
        Some(HashMap::from([(felt_to_hash(&class_hash), contract_class)])),
    );

    let calldata = match &args.inputs {
        Some(vec) => vec.iter().map(|&n| n.into()).collect(),
        None => Vec::new(),
    };

    let exec_entry_point = ExecutionEntryPoint::new(
        Address(contract_address.clone()),
        calldata.clone(),
        entrypoint_selector.clone(),
        Address(0.into()),
        *entry_point_type,
        Some(CallType::Delegate),
        Some(felt_to_hash(&class_hash)),
    );

    let general_config = StarknetGeneralConfig::default();
    let tx_execution_context = TransactionExecutionContext::new(
        Address(0.into()),
        Felt::zero(),
        Vec::new(),
        0,
        10.into(),
        general_config.invoke_tx_max_n_steps(),
        TRANSACTION_VERSION,
    );
    let mut resources_manager = ExecutionResourcesManager::default();

    exec_entry_point
        .execute(
            &mut state,
            &general_config,
            &mut resources_manager,
            &tx_execution_context,
        )
        .map_err(ParserError::ExecuteFromEntryPointError)?;

    let tx_hash = calculate_transaction_hash_common(
        TransactionHashPrefix::Invoke,
        0,
        Address(contract_address),
        entrypoint_selector,
        &calldata,
        0,
        Felt::zero(),
        &[],
    )
    .map_err(ParserError::ComputeTransactionHashError)?;

    println!(
        "Invoke transaction was sent.\nContract address: {}\nTransaction hash: 0x{:x}",
        &args.address,
        tx_hash.to_bigint()
    );
    Ok(())
}

fn main() -> Result<(), ParserError> {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Declare(declare_args) => declare_parser(declare_args),
        Commands::Deploy(deploy_args) => deploy_parser(deploy_args),
        Commands::Invoke(invoke_args) => invoke_parser(invoke_args),
    }?;
    Ok(())
}
