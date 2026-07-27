#![forbid(unsafe_code)]

mod attestation;

use anyhow::{Context as _, Result, bail};
use attestation::{DEFAULT_BASE_URL, DEFAULT_TLS_DOMAIN, verify_first_contact};
use clap::{Args, Parser, Subcommand};
use revm::{
    Context, ExecuteEvm, MainBuilder, MainContext,
    context::TxEnv,
    context_interface::result::{ExecutionResult, Output},
    primitives::TxKind,
    state::AccountInfo,
};
use safe_node_revm::{
    Address, B256, BlockSelector, Bytes, NativeClientConfig, PinnedHttpTransport, RateClient,
    SEPOLIA_WETH9_FIXTURE, SafeNodeDb, SchedulerConfig, U256,
};
use serde::Deserialize;
use std::{str::FromStr, sync::Arc, time::Duration};

const DEFAULT_RPC_URL: &str = "https://rpc-gcp.safe-node.com/olabs-api-6f66df6d6bd1669ed0b2c3c4b2ef8e4307b334b8be7a2f3f6dcae10ada44f82b/json_rpc";

#[derive(Parser, Debug)]
#[command(name = "safe-revm", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    /// Verify TDX first contact and print the discovered SPKI pin.
    Attest(AttestArgs),
    /// Attest if needed, then execute a proof-backed revm call.
    Run(RunArgs),
}

#[derive(Args, Clone, Debug)]
struct AttestArgs {
    #[arg(long, env = "SAFE_NODE_BASE_URL", default_value = DEFAULT_BASE_URL)]
    base_url: String,
    #[arg(long, env = "SAFE_NODE_TLS_DOMAIN", default_value = DEFAULT_TLS_DOMAIN)]
    tls_domain: String,
}

#[derive(Args, Clone, Debug)]
struct RunArgs {
    #[command(flatten)]
    attest: AttestArgs,
    #[arg(long, env = "SAFE_NODE_RPC_URL", default_value = DEFAULT_RPC_URL)]
    rpc_url: String,
    /// Reuse only a pin produced by a previous successful `safe-revm attest`.
    #[arg(long, env = "SAFE_NODE_TLS_PIN")]
    pin: Option<String>,
    #[arg(long, default_value = "0xad19c3")]
    block: String,
    #[arg(
        long,
        default_value = "0x6d582d06dd8420c98ba0fa587b80cfb98a476a4f1ca882d8dfecbf4207b30a4e"
    )]
    state_root: String,
    #[arg(long, default_value = "0xfff9976782d46cc05630d1f6ebab18b2324d6b14")]
    contract: String,
    #[arg(long, default_value = "0x06fdde03")]
    calldata: String,
    /// Override the fixture's preloaded bytecode.
    #[arg(long, env = "SAFE_NODE_BYTECODE")]
    bytecode: Option<String>,
    #[arg(long, default_value_t = 4)]
    requests_per_second: u32,
    #[arg(long, default_value_t = 1)]
    storage_keys_per_request: usize,
    #[arg(long, default_value_t = 10, value_parser = clap::value_parser!(u8).range(1..=10))]
    max_attempts: u8,
    #[arg(long, default_value_t = 20)]
    request_timeout_seconds: u64,
    /// Continue cover traffic briefly after execution. Real applications should
    /// choose a longer lifecycle unrelated to one execution.
    #[arg(long, default_value_t = 2)]
    cover_tail_seconds: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fixture {
    slot: U256,
    code: Bytes,
    expected_return_string: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Attest(args) => {
            let result = verify_first_contact(&args.base_url, &args.tls_domain).await?;
            print!("{}", result.transcript);
            eprintln!("policy_checked_workload_digest={}", result.workload_digest);
        }
        Command::Run(args) => run(args).await?,
    }
    Ok(())
}

async fn run(args: RunArgs) -> Result<()> {
    let fixture: Fixture = serde_json::from_str(SEPOLIA_WETH9_FIXTURE)?;
    let pin = match args.pin {
        Some(pin) => pin,
        None => {
            let result =
                verify_first_contact(&args.attest.base_url, &args.attest.tls_domain).await?;
            eprintln!("TDX first contact verified; using {}", result.pin);
            result.pin
        }
    };

    let block = parse_quantity_u64(&args.block).context("invalid block number")?;
    let state_root = B256::from_str(&args.state_root).context("invalid state root")?;
    let contract = Address::from_str(&args.contract).context("invalid contract address")?;
    let calldata = Bytes::from_str(&args.calldata).context("invalid calldata")?;
    let bytecode = match args.bytecode {
        Some(value) => Bytes::from_str(&value).context("invalid bytecode")?,
        None => fixture.code,
    };

    let transport = Arc::new(PinnedHttpTransport::new(
        &args.rpc_url,
        &args.attest.tls_domain,
        &pin,
        Duration::from_secs(args.request_timeout_seconds),
    )?);
    let client = RateClient::start(
        NativeClientConfig {
            scheduler: SchedulerConfig {
                block: BlockSelector::Number(block),
                storage_keys_per_request: args.storage_keys_per_request,
                dummy_address: contract,
                dummy_slot: fixture.slot,
            },
            state_root,
            requests_per_second: args.requests_per_second,
            max_attempts: args.max_attempts,
        },
        transport,
    )?;

    let caller = Address::repeat_byte(0x11);
    let mut db = SafeNodeDb::new(client.clone());
    let loaded_hash = db.preload_bytecode_at(contract, bytecode);
    db.preload_local_account(caller, AccountInfo::default().with_balance(U256::MAX));
    db.preload_local_account(Address::ZERO, AccountInfo::default());
    eprintln!("preloaded_code_hash={loaded_hash:#x}");

    let mut evm = Context::mainnet()
        .with_db(db)
        .modify_block_chained(|block_env| block_env.number = U256::from(block))
        .modify_cfg_chained(|cfg| cfg.chain_id = 11_155_111)
        .build_mainnet();
    let result = evm.transact_one(
        TxEnv::builder()
            .caller(caller)
            .kind(TxKind::Call(contract))
            .data(calldata)
            .gas_limit(1_000_000)
            .chain_id(Some(11_155_111))
            .build()
            .map_err(|error| anyhow::anyhow!(error.to_string()))?,
    )?;
    let output = match result {
        ExecutionResult::Success {
            output: Output::Call(output),
            gas,
            ..
        } => {
            println!("execution_success=true");
            println!("gas_used={}", gas.tx_gas_used());
            output
        }
        other => bail!("execution did not succeed: {other:?}"),
    };
    println!("return_data=0x{}", hex_bytes(&output));
    if let Some(value) = decode_abi_string(&output) {
        println!("return_string={value}");
        if contract == Address::from_str("0xfff9976782d46cc05630d1f6ebab18b2324d6b14")?
            && block == 11_344_323
        {
            anyhow::ensure!(
                value == fixture.expected_return_string,
                "unexpected WETH name"
            );
        }
    }

    tokio::time::sleep(Duration::from_secs(args.cover_tail_seconds)).await;
    client.stop();
    Ok(())
}

fn parse_quantity_u64(value: &str) -> Result<u64, std::num::ParseIntError> {
    u64::from_str_radix(value.strip_prefix("0x").unwrap_or(value), 16)
}

fn hex_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_abi_string(bytes: &[u8]) -> Option<String> {
    if bytes.len() < 64 {
        return None;
    }
    let offset = usize::try_from(U256::from_be_slice(&bytes[..32])).ok()?;
    let length_end = offset.checked_add(32)?;
    let length = usize::try_from(U256::from_be_slice(bytes.get(offset..length_end)?)).ok()?;
    let value_end = length_end.checked_add(length)?;
    String::from_utf8(bytes.get(length_end..value_end)?.to_vec()).ok()
}
