

// 1. Help
// 2. Ejecutar tx y mostrar receipt
// 3. Ejecutar bloque y mostrar receipt
// 4. Ejecutar rango de bloques.

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(about = "Replay is a tool for executing Starknet transactions.", long_about = None)]
struct ReplayArgs {
    #[command(subcommand)]
    subcommand: ReplaySubCommand,
    // /// Display the help text.
    // #[arg(short, long)]
    // help: bool,
    // #[arg(long)]
    // tx: String,
    // #[arg(long)]
    // block: String,
    // #[arg(long)]
    // execute_range: (String, String)
}

#[derive(Subcommand, Debug)]
enum ReplaySubCommand {
    Help,
    ExecuteSingleTx { tx_hash: String },
    ExecuteTxRange { tx_start: String, tx_end: String },
    ExecuteSingleBlock { block_number: String },
    ExecuteBlockRange { block_start: String, block_end: String },
}

fn main() {
    println!("Hello, world!");
}
