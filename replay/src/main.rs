

// 1. Help
// 2. Ejecutar tx y mostrar receipt
// 3. Ejecutar bloque y mostrar receipt
// 4. Ejecutar rango de bloques.

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(about = "Replay is a tool for executing Starknet transactions.", long_about = None)]
struct ReplayCLI {
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
    // #[clap(long = "execute-tx")] 
    ExecuteSingleTx { tx_hash: String },
    ExecuteTxRange { tx_start: String, tx_end: String },
    ExecuteSingleBlock { block_number: String },
    ExecuteBlockRange { block_start: String, block_end: String },
}

fn main() {
    let cli = ReplayCLI::parse();
    println!("{:?}", cli);
    // You can check for the existence of subcommands, and if found use their
    // matches just as you would the top level cmd

}
