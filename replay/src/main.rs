use clap::{Parser, Subcommand};
use rpc_state_reader::{
    rpc_state::{RpcChain, RpcTransactionReceipt, TransactionTrace}, execute_tx_configurable, execute_tx,
};
use starknet_api::block::BlockNumber;
use starknet_in_rust::execution::TransactionExecutionInfo;

#[derive(Debug, Parser)]
#[command(about = "Replay is a tool for executing Starknet transactions.", long_about = None)]
struct ReplayCLI {
    #[command(subcommand)]
    subcommand: ReplayExecute,
}

#[derive(Subcommand, Debug)]
enum ReplayExecute {
    #[clap(about = "Execute a single transaction given a transaction hash.")]
    Tx {
        tx_hash: String,
        chain: String,
        block_number: u64,
        silent: Option<bool>,
    },
    #[clap(about = "Execute all the invoke transactions in a given block.")]
    Block { block_number: u64, chain: String, silent: Option<bool> },
    #[clap(about = "Execute all the invoke transactions in a given range of blocks.")]
    BlockRange {
        block_start: u64,
        block_end: u64,
        chain: String,
        silent: Option<bool>,
    },
}

fn main() {
    let cli = ReplayCLI::parse();

    match cli.subcommand {
        ReplayExecute::Tx {
            tx_hash,
            chain,
            block_number,
            silent
        } => {
            let rpc_chain = parse_network(&chain);
            let block_number = BlockNumber(block_number-1);

            let (tx_info, )trace, receipt) = execute_tx(&tx_hash, rpc_chain, block_number).unwrap();

            let TransactionExecutionInfo {
                revert_error,
                actual_fee,
                ..
            } = tx_info;
            
            let sir_actual_fee = actual_fee;

            // let TransactionTrace {
            //     validate_invocation,
            //     function_invocation,
            //     fee_transfer_invocation,
            //     ..
            // } = trace;

            let RpcTransactionReceipt {
                actual_fee,
                execution_status,
                ..
            } = receipt;

            if let Some(true) = silent {
                println!("Transaction hash: {}", tx_hash);
                println!("Block number: {}", block_number.0);
                println!("Chain: {}", chain);
                println!("[RPC] Execution status: {:?}", execution_status);
                if let Some(revert_error) = revert_error {
                    println!("[SIR] Revert error: {}", revert_error);
                }
                println!("[RPC] Actual fee: {} wei", actual_fee);
                println!("[SIR] Actual fee: {} wei", sir_actual_fee);
            }
        }
        ReplayExecute::Block {
            block_number,
            chain,
            silent
        } => {

        }
        ReplayExecute::BlockRange {
            block_start,
            block_end,
            chain,
            silent
        } => {

        }
    }
}


fn parse_network(network: &str) -> RpcChain {
    match network.to_lowercase().as_str() {
        "mainnet" => RpcChain::MainNet,
        "testnet" => RpcChain::TestNet,
        "testnet2" => RpcChain::TestNet2,
        _ => panic!("Invalid network name, it should be one of: mainnet, testnet, testnet2"),
    }
}
