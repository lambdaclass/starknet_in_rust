

// 1. Help
// 2. Ejecutar tx y mostrar receipt
// 3. Ejecutar bloque y mostrar receipt
// 4. Ejecutar rango de bloques.

use clap::{Parser, Subcommand};

#[derive(Debug, Parser)]
#[command(about = "Replay is a tool for executing Starknet transactions.", long_about = None)]
struct ReplayArgs {
    /// Display the help text.
    #[arg(short, long)]
    help: bool,
    #[arg(long)]
    tx: String,
    #[arg(long)]
    block: String,
    #[arg(long)]
    execute_range: (String, String)
}

#[derive(Subcommand, Debug)]
struct ExecuteBlockRange {
    start: String,
    end: String,
}

fn main() {
    println!("Hello, world!");
}
