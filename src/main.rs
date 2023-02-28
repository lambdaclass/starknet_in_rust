use clap::{Args, Parser, Subcommand};
use starknet_rs::{
    core::contract_address::starknet_contract_address::compute_class_hash,
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
}

#[derive(Args)]
struct DeclareArgs {
    #[arg(long)]
    contract: std::path::PathBuf,
}

/*#[derive(Args)]
struct DeployArgs {
    #[arg(long)]
    class_hash: String,
}*/

fn declare_parser(args: &DeclareArgs) {
    let contract_class = ContractClass::try_from(&args.contract).unwrap();
    let class_hash = compute_class_hash(&contract_class).unwrap();
    println!(
        "Declare transaction was sent.\nContract class hash: 0x{:x}\nTransaction hash: 0x",
        class_hash.to_biguint()
    );
}

fn main() {
    let cli = Cli::parse();
    match &cli.command {
        Commands::Declare(declare_args) => declare_parser(declare_args),
    };
}
