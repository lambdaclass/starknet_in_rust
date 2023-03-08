use actix_web::{post, web, App, HttpResponse, HttpServer};
use clap::{Args, Parser, Subcommand};
use felt::Felt;
use num_traits::{Num, Zero};
use serde::{Deserialize, Serialize};
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
        state::{
            cached_state::CachedState,
            state_api::{State, StateReader},
        },
    },
    core::{
        contract_address::starknet_contract_address::compute_class_hash,
        transaction_hash::starknet_transaction_hash::{
            calculate_declare_transaction_hash, calculate_deploy_transaction_hash,
            calculate_transaction_hash_common, TransactionHashPrefix,
        },
    },
    definitions::{
        constants::{DECLARE_VERSION, TRANSACTION_VERSION},
        general_config::StarknetGeneralConfig,
    },
    hash_utils::calculate_contract_address,
    parser_errors::ParserError,
    serde_structs::contract_abi::read_abi,
    services::api::contract_class::ContractClass,
    utils::{felt_to_hash, string_to_hash, Address},
};
use std::{collections::HashMap, path::PathBuf, sync::Mutex};

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
    Devnet(DevnetArgs),
}

#[derive(Args, Serialize, Deserialize)]
pub struct DeclareArgs {
    #[arg(long)]
    contract: PathBuf,
}

#[derive(Args, Serialize, Deserialize)]
struct DeployArgs {
    #[arg(long = "class_hash")]
    class_hash: String,
    #[arg(long, default_value = "1111")]
    salt: i32,
    #[arg(long, num_args=1.., value_delimiter = ' ')]
    inputs: Option<Vec<i32>>,
}

#[derive(Args, Serialize, Deserialize)]
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

#[derive(Args)]
struct DevnetArgs {
    #[arg(long, default_value = "7878")]
    port: u16,
}

struct AppState {
    cached_state: Mutex<CachedState<InMemoryStateReader>>,
}

fn declare_parser(
    cached_state: &mut CachedState<InMemoryStateReader>,
    args: &DeclareArgs,
) -> Result<(), ParserError> {
    let contract_class =
        ContractClass::try_from(&args.contract).map_err(ParserError::OpenFileError)?;
    let class_hash =
        compute_class_hash(&contract_class).map_err(ParserError::ComputeClassHashError)?;
    cached_state
        .set_contract_class(&felt_to_hash(&class_hash), &contract_class)
        .map_err(ParserError::StateError)?;

    let tx_hash = calculate_declare_transaction_hash(
        contract_class,
        Felt::zero(),
        Address(0.into()),
        0,
        DECLARE_VERSION,
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

fn deploy_parser(
    cached_state: &mut CachedState<InMemoryStateReader>,
    args: &DeployArgs,
) -> Result<(), ParserError> {
    let constructor_calldata = match &args.inputs {
        Some(vec) => vec.iter().map(|&n| n.into()).collect(),
        None => Vec::new(),
    };
    let address = calculate_contract_address(
        &Address(args.salt.into()),
        &Felt::from_str_radix(&args.class_hash[2..], 16)
            .map_err(|_| ParserError::ParseHashError(args.class_hash.clone()))?,
        &constructor_calldata,
        Address(0.into()),
    )
    .map_err(ParserError::ComputeAddressError)?;

    cached_state
        .deploy_contract(Address(address.clone()), string_to_hash(&args.class_hash))
        .map_err(ParserError::StateError)?;
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

fn invoke_parser(
    mut cached_state: CachedState<InMemoryStateReader>,
    args: &InvokeArgs,
) -> Result<(), ParserError> {
    let contract_address = Felt::from_str_radix(&args.address[2..], 16).unwrap();
    let class_hash = cached_state
        .get_class_hash_at(&Address(contract_address.clone()))
        .unwrap();
    let contract_class = cached_state.get_contract_class(&class_hash).unwrap();
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

    let contract_state = ContractState::new(class_hash.clone(), 0.into(), HashMap::new());
    cached_state
        .state_reader()
        .contract_states_mut()
        .insert(Address(contract_address.clone()), contract_state);

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
        Some(*class_hash),
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
            &mut cached_state,
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

async fn devnet_parser(devnet_args: &DevnetArgs) -> Result<(), ParserError> {
    start_devnet(devnet_args.port)
        .await
        .map_err(ParserError::ServerError)?;
    Ok(())
}

#[post("/declare")]
async fn declare_req(data: web::Data<AppState>, args: web::Json<DeclareArgs>) -> HttpResponse {
    let mut cached_state = data.cached_state.lock().unwrap();
    match declare_parser(&mut cached_state, &args) {
        Ok(_) => HttpResponse::Ok().body("declared!"),
        Err(e) => HttpResponse::ExpectationFailed().body(e.to_string()),
    }
}

#[post("/deploy")]
async fn deploy_req(data: web::Data<AppState>, args: web::Json<DeployArgs>) -> HttpResponse {
    let mut cached_state = data.cached_state.lock().unwrap();
    match deploy_parser(&mut cached_state, &args) {
        Ok(_) => HttpResponse::Ok().body("declared!"),
        Err(e) => HttpResponse::ExpectationFailed().body(e.to_string()),
    }
}

#[post("/invoke")]
async fn invoke_req(data: web::Data<AppState>, args: web::Json<InvokeArgs>) -> HttpResponse {
    let cached_state = data.cached_state.lock().unwrap().to_owned();
    match invoke_parser(cached_state, &args) {
        Ok(_) => HttpResponse::Ok().body("declared!"),
        Err(e) => HttpResponse::ExpectationFailed().body(e.to_string()),
    }
}

pub async fn start_devnet(port: u16) -> Result<(), std::io::Error> {
    let cached_state = web::Data::new(AppState {
        cached_state: Mutex::new(CachedState::<InMemoryStateReader>::new(
            InMemoryStateReader::new(HashMap::new(), HashMap::new()),
            Some(HashMap::new()),
        )),
    });

    HttpServer::new(move || {
        App::new()
            .app_data(cached_state.clone())
            .service(declare_req)
            .service(deploy_req)
            .service(invoke_req)
    })
    .bind(("127.0.0.1", port))?
    .run()
    .await
}

#[actix_web::main]
async fn main() -> Result<(), ParserError> {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Declare(declare_args) => {
            let response = awc::Client::new()
                .post("http://127.0.0.1:7878/declare")
                .send_json(&declare_args)
                .await;
            let body = response.unwrap().body().await;
            println!("{body:?}");
            Ok(())
        }
        Commands::Deploy(deploy_args) => {
            let response = awc::Client::new()
                .post("http://127.0.0.1:7878/deploy")
                .send_json(&deploy_args)
                .await;
            let body = response.unwrap().body().await;
            println!("{body:?}");
            Ok(())
        }
        Commands::Invoke(invoke_args) => {
            let response = awc::Client::new()
                .post("http://127.0.0.1:7878/invoke")
                .send_json(&invoke_args)
                .await;
            let body = response.unwrap().body().await;
            println!("{body:?}");
            Ok(())
        }
        Commands::Devnet(devnet_args) => devnet_parser(devnet_args).await,
    }?;
    Ok(())
}
