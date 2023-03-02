use clap::{Args, Parser, Subcommand};
use starknet_rs::{
    core::contract_address::starknet_contract_address::compute_class_hash,
    server::{add_class_hash, retrieve_contract_name},
    services::api::contract_class::ContractClass,
};

#[derive(Parser)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    Declare(DeclareArgs),
    Deploy(DeployArgs),
}

#[derive(Args)]
struct DeclareArgs {
    #[arg(long)]
    contract: std::path::PathBuf,
}

#[derive(Args)]
struct DeployArgs {
    #[arg(long)]
    class_hash: String,
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
    let class_hash = args.class_hash[2..].to_string();
    let contract_name = retrieve_contract_name(&class_hash);
    let contract_class = ContractClass::try_from(&contract_name);
    println!("{}:{:?}", class_hash, contract_class);
}

fn main() {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Declare(declare_args) => declare_parser(declare_args),
        Commands::Deploy(deploy_args) => deploy_parser(deploy_args),
    };
}
