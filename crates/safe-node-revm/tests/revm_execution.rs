#![cfg(not(target_arch = "wasm32"))]

use alloy_primitives::{Address, B256, Bytes, U256};
use async_trait::async_trait;
use revm::{
    Context, ExecuteEvm, MainBuilder, MainContext,
    context::TxEnv,
    context_interface::result::{ExecutionResult, Output},
    primitives::TxKind,
    state::AccountInfo,
};
use safe_node_revm::{
    BlockSelector, GetProofResponse, JsonRpcRequest, JsonRpcResponse, NativeClientConfig,
    RateClient, RpcTransport, SEPOLIA_WETH9_FIXTURE, SafeNodeDb, SchedulerConfig, TransportError,
};
use serde::Deserialize;
use serde_json::Value;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fixture {
    block: String,
    state_root: B256,
    address: Address,
    slot: U256,
    code: Bytes,
    calldata: Bytes,
    expected_return_string: String,
    proof: GetProofResponse,
}

fn fixture() -> Fixture {
    serde_json::from_str(SEPOLIA_WETH9_FIXTURE).unwrap()
}

#[derive(Debug)]
struct FixtureTransport {
    fixture: Fixture,
    requests: Mutex<Vec<JsonRpcRequest>>,
}

#[async_trait]
impl RpcTransport for FixtureTransport {
    async fn send(&self, request: JsonRpcRequest) -> Result<JsonRpcResponse, TransportError> {
        self.requests.lock().unwrap().push(request.clone());
        let keys = request.storage_keys();
        let mut proof = self.fixture.proof.clone();
        if keys.is_empty() {
            proof.storage_proof.clear();
        } else {
            let template = proof.storage_proof[0].clone();
            proof.storage_proof = keys
                .into_iter()
                .map(|key| {
                    assert_eq!(key, self.fixture.slot);
                    let mut entry = template.clone();
                    entry.key = key;
                    entry
                })
                .collect();
        }
        Ok(JsonRpcResponse {
            jsonrpc: "2.0".to_owned(),
            id: Value::String(request.id),
            result: Some(proof),
            error: None,
        })
    }
}

#[test]
fn executes_preloaded_weth_code_with_proof_backed_storage() {
    let fixture = fixture();
    let block = u64::from_str_radix(fixture.block.trim_start_matches("0x"), 16).unwrap();
    let transport = Arc::new(FixtureTransport {
        fixture: fixture.clone(),
        requests: Mutex::new(Vec::new()),
    });
    let client = RateClient::start(
        NativeClientConfig {
            scheduler: SchedulerConfig {
                block: BlockSelector::Number(block),
                storage_keys_per_request: 1,
                dummy_address: fixture.address,
                dummy_slot: fixture.slot,
            },
            state_root: fixture.state_root,
            requests_per_second: 1_000,
            max_attempts: 10,
        },
        transport.clone(),
    )
    .unwrap();

    let caller = Address::repeat_byte(0x11);
    let mut db = SafeNodeDb::new(client.clone());
    db.preload_bytecode_at(fixture.address, fixture.code.clone());
    db.preload_local_account(caller, AccountInfo::default().with_balance(U256::MAX));
    // The default block beneficiary is zero and is touched during fee accounting.
    db.preload_local_account(Address::ZERO, AccountInfo::default());

    let mut evm = Context::mainnet()
        .with_db(db)
        .modify_block_chained(|block_env| block_env.number = U256::from(block))
        .modify_cfg_chained(|cfg| cfg.chain_id = 11_155_111)
        .build_mainnet();
    let result = evm
        .transact_one(
            TxEnv::builder()
                .caller(caller)
                .kind(TxKind::Call(fixture.address))
                .data(fixture.calldata.clone())
                .gas_limit(1_000_000)
                .chain_id(Some(11_155_111))
                .build()
                .unwrap(),
        )
        .unwrap();

    let bytes = match result {
        ExecutionResult::Success {
            output: Output::Call(bytes),
            ..
        } => bytes,
        other => panic!("execution failed: {other:?}"),
    };
    assert_eq!(decode_abi_string(&bytes), fixture.expected_return_string);

    let requests = transport.requests.lock().unwrap();
    assert!(
        requests
            .iter()
            .any(|request| request.storage_keys().is_empty())
    );
    assert!(
        requests
            .iter()
            .any(|request| request.storage_keys() == vec![fixture.slot])
    );
    client.stop();
}

fn decode_abi_string(bytes: &[u8]) -> String {
    assert!(bytes.len() >= 64);
    let offset = usize::try_from(U256::from_be_slice(&bytes[..32])).unwrap();
    let length = usize::try_from(U256::from_be_slice(&bytes[offset..offset + 32])).unwrap();
    String::from_utf8(bytes[offset + 32..offset + 32 + length].to_vec()).unwrap()
}
