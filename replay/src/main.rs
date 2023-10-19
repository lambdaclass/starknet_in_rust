use clap::{Parser, Subcommand};
use rpc_state_reader::{
    execute_tx,
    rpc_state::{BlockValue, RpcChain, RpcState, RpcTransactionReceipt, TransactionTrace},
    RpcStateReader,
};
use starknet_api::{block::BlockNumber, core::ChainId, transaction::TransactionReceipt};
use starknet_in_rust::execution::TransactionExecutionInfo;

#[derive(Debug, Parser)]
#[command(about = "Replay is a tool for executing Starknet transactions.", long_about = None)]
struct ReplayCLI {
    #[command(subcommand)]
    subcommand: ReplaySubCommand,
}

#[derive(Subcommand, Debug)]
enum ReplaySubCommand {
    #[clap(about = "Execute a single transaction given a transaction hash.")]
    ExecuteTx {
        tx_hash: String,
        chain: String,
        block_number: u64,
    },
    #[clap(about = "Execute all the invoke transactions in a given block.")]
    ExecuteBlock { block_number: u64, chain: String },
    #[clap(about = "Execute all the invoke transactions in a given range of blocks.")]
    ExecuteBlockRange {
        block_start: u64,
        block_end: u64,
        chain: String,
    },
}

fn main() {
    let cli = ReplayCLI::parse();

    match cli.subcommand {
        ReplaySubCommand::ExecuteTx {
            tx_hash,
            chain,
            block_number,
        } => {
            let rpc_chain: RpcChain = match chain.as_str() {
                "mainnet" => RpcChain::MainNet,
                "testnet" => RpcChain::TestNet,
                "testnet2" => RpcChain::TestNet2,
                _ => panic!("Invalid chain name"),
            };
            let block_number = BlockNumber(block_number);

            let (tx_info, trace, receipt) = execute_tx(&tx_hash, rpc_chain, block_number);

            let TransactionExecutionInfo {
                call_info,
                validate_info,
                fee_transfer_info,
                revert_error,
                actual_fee,
                ..
            } = tx_info;

            let TransactionTrace {
                validate_invocation,
                function_invocation,
                fee_transfer_invocation,
                ..
            } = trace;

            let RpcTransactionReceipt {
                actual_fee,
                execution_status,
                ..
            } = receipt;
        }
        ReplaySubCommand::ExecuteBlock {
            block_number,
            chain,
        } => {}
        ReplaySubCommand::ExecuteBlockRange {
            block_start,
            block_end,
            chain,
        } => {}
    }
}
