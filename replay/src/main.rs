use clap::{Parser, Subcommand};
use rpc_state_reader::{
    execute_tx_configurable, get_transaction_hashes,
    rpc_state::{RpcChain, RpcTransactionReceipt},
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
    Block {
        chain: String,
        block_number: u64,
        silent: Option<bool>,
    },
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
            silent,
        } => {
            show_execution_data(tx_hash, &chain, block_number, silent);
        }
        ReplayExecute::Block {
            block_number,
            chain,
            silent,
        } => {
            println!("Executing block number: {}", block_number);
            let rpc_chain = parse_network(&chain);
            let block_number = BlockNumber(block_number);
            let transaction_hashes = get_transaction_hashes(block_number, rpc_chain)
                .expect("Unable to fetch the transaction hashes.");

            for tx_hash in transaction_hashes {
                show_execution_data(tx_hash, &chain, block_number.0, silent);
            }
        }
        ReplayExecute::BlockRange {
            block_start,
            block_end,
            chain,
            silent,
        } => {
            println!("Executing block range: {} - {}", block_start, block_end);
            let rpc_chain = parse_network(&chain);
            for block_number in block_start..=block_end {
                let block_number = BlockNumber(block_number);
                let transaction_hashes = get_transaction_hashes(block_number, rpc_chain)
                    .expect("Unable to fetch the transaction hashes.");

                for tx_hash in transaction_hashes {
                    show_execution_data(tx_hash, &chain, block_number.0, silent);
                }
            }
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

fn show_execution_data(tx_hash: String, chain: &str, block_number: u64, silent: Option<bool>) {
    let rpc_chain = parse_network(chain);
    if silent.is_none() || !silent.unwrap() {
        println!("Executing transaction with hash: {}", tx_hash);
        println!("Block number: {}", block_number);
        println!("Chain: {}", chain);
    }
    let previous_block_number = BlockNumber(block_number - 1);

    let (tx_info, _trace, receipt) =
        match execute_tx_configurable(&tx_hash, rpc_chain, previous_block_number, false, true) {
            Ok(x) => x,
            Err(error_reason) => {
                println!("Error: {}", error_reason);
                return;
            }
        };
    let TransactionExecutionInfo {
        revert_error,
        actual_fee,
        ..
    } = tx_info;

    let sir_actual_fee = actual_fee;

    let RpcTransactionReceipt {
        actual_fee,
        execution_status,
        ..
    } = receipt;

    if silent.is_none() || !silent.unwrap() {
        println!("[RPC] Execution status: {:?}", execution_status);
        if let Some(revert_error) = revert_error {
            println!("[SIR] Revert error: {}", revert_error);
        }
        println!("[RPC] Actual fee: {} wei", actual_fee);
        println!("[SIR] Actual fee: {} wei", sir_actual_fee);
    }
}
