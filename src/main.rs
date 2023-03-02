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
    core::contract_address::starknet_contract_address::compute_class_hash,
    definitions::{constants::TRANSACTION_VERSION, general_config::StarknetGeneralConfig},
    hash_utils::calculate_contract_address,
    serde_structs::contract_abi::read_abi,
    server::{
        add_address, add_class_hash, get_contract_from_address, get_contract_from_class_hash,
    },
    services::api::contract_class::{ContractClass, EntryPointType},
    starknet_storage::dict_storage::DictStorage,
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

fn declare_parser(args: &DeclareArgs) {
    let contract_class = ContractClass::try_from(&args.contract).unwrap();
    let class_hash = compute_class_hash(&contract_class).unwrap();
    add_class_hash(&(&class_hash).to_biguint().to_str_radix(16), &args.contract);
    println!(
        "Declare transaction was sent.\nContract class hash: 0x{:x}\nTransaction hash: 0x",
        class_hash.to_biguint()
    );
}

fn deploy_parser(args: &DeployArgs) {
    let contract_name = get_contract_from_class_hash(&args.class_hash[2..].to_string());
    let constructor_calldata = match &args.inputs {
        Some(vec) => vec.iter().map(|&n| n.into()).collect(),
        None => Vec::new(),
    };
    let address = calculate_contract_address(
        &Address(args.salt.into()),
        &Felt::from_str_radix(&args.class_hash[2..], 16).unwrap(),
        &constructor_calldata,
        Address(0.into()),
    )
    .unwrap();
    add_address(&address.to_str_radix(16), &contract_name);
    println!("Invoke transaction for contract deployment was sent.\nContract address: 0x{:x}\nTransaction hash: 0x", address.to_biguint());
}

fn invoke_parser(args: &InvokeArgs) {
    let contract_name = get_contract_from_address(&args.address[2..].to_string());
    let contract_address = Felt::from_str_radix(&args.address[2..].to_string(), 16).unwrap();
    let contract_class = ContractClass::try_from(contract_name).unwrap();
    let class_hash = compute_class_hash(&contract_class).unwrap();
    let function_entrypoint_indexes = read_abi(&args.abi);

    let entry_points_by_type = contract_class.entry_points_by_type().clone();

    let entrypoint_selector = entry_points_by_type
        .get(&EntryPointType::External)
        .unwrap()
        .get(*function_entrypoint_indexes.get(&args.function).unwrap())
        .unwrap()
        .selector()
        .clone();

    let contract_state = ContractState::new(felt_to_hash(&class_hash), 3.into(), HashMap::new());

    let mut state_reader = InMemoryStateReader::new(DictStorage::new(), DictStorage::new());
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
        Address(contract_address),
        calldata,
        entrypoint_selector,
        Address(0.into()),
        EntryPointType::External,
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

    let data = exec_entry_point
        .execute(
            &mut state,
            &general_config,
            &mut resources_manager,
            &tx_execution_context,
        )
        .unwrap();
    println!("{data:?}");
}

fn main() {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Declare(declare_args) => declare_parser(declare_args),
        Commands::Deploy(deploy_args) => deploy_parser(deploy_args),
        Commands::Invoke(invoke_args) => invoke_parser(invoke_args),
    };
}
