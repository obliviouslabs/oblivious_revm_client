#![cfg(not(target_arch = "wasm32"))]

use async_trait::async_trait;
use safe_node_revm::{
    Address, B256, BlockSelector, GetProofResponse, JsonRpcError, JsonRpcRequest, JsonRpcResponse,
    NativeClientConfig, RateClient, RpcTransport, SEPOLIA_WETH9_FIXTURE, SafeNodeError,
    SchedulerConfig, TransportError, U256,
};
use serde::Deserialize;
use serde_json::Value;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

#[derive(Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fixture {
    block: String,
    state_root: B256,
    address: Address,
    slot: U256,
    proof: GetProofResponse,
}

fn fixture() -> Fixture {
    serde_json::from_str(SEPOLIA_WETH9_FIXTURE).unwrap()
}

#[derive(Debug)]
struct FlakyTransport {
    real_address: Address,
    proof: GetProofResponse,
    fail_real: usize,
    real_calls: AtomicUsize,
}

#[async_trait]
impl RpcTransport for FlakyTransport {
    async fn send(&self, request: JsonRpcRequest) -> Result<JsonRpcResponse, TransportError> {
        let real = request.address() == self.real_address;
        let call = real.then(|| self.real_calls.fetch_add(1, Ordering::SeqCst) + 1);
        let mut envelope = JsonRpcResponse {
            jsonrpc: "2.0".to_owned(),
            id: Value::String(request.id),
            result: None,
            error: None,
        };
        if !real || call.unwrap() <= self.fail_real {
            envelope.error = Some(JsonRpcError {
                code: -32001,
                message: "data unavailable".to_owned(),
                data: None,
            });
        } else {
            let mut proof = self.proof.clone();
            proof.storage_proof.clear();
            envelope.result = Some(proof);
        }
        Ok(envelope)
    }
}

fn client(fixture: &Fixture, transport: Arc<FlakyTransport>, max_attempts: u8) -> Arc<RateClient> {
    let block = u64::from_str_radix(fixture.block.trim_start_matches("0x"), 16).unwrap();
    RateClient::start(
        NativeClientConfig {
            scheduler: SchedulerConfig {
                block: BlockSelector::Number(block),
                storage_keys_per_request: 1,
                dummy_address: Address::repeat_byte(0xdd),
                dummy_slot: fixture.slot,
            },
            state_root: fixture.state_root,
            requests_per_second: 1_000,
            max_attempts,
        },
        transport,
    )
    .unwrap()
}

#[test]
fn transient_errors_consume_later_ticks_then_succeed() {
    let fixture = fixture();
    let transport = Arc::new(FlakyTransport {
        real_address: fixture.address,
        proof: fixture.proof.clone(),
        fail_real: 2,
        real_calls: AtomicUsize::new(0),
    });
    let client = client(&fixture, transport.clone(), 10);
    assert!(
        client
            .get_proof(fixture.address, &[])
            .unwrap()
            .account
            .is_some()
    );
    assert_eq!(transport.real_calls.load(Ordering::SeqCst), 3);
    client.stop();
}

#[test]
fn retries_stop_at_configured_maximum() {
    let fixture = fixture();
    let transport = Arc::new(FlakyTransport {
        real_address: fixture.address,
        proof: fixture.proof.clone(),
        fail_real: usize::MAX,
        real_calls: AtomicUsize::new(0),
    });
    let client = client(&fixture, transport.clone(), 3);
    let error = client.get_proof(fixture.address, &[]).unwrap_err();
    assert!(matches!(
        error,
        SafeNodeError::AttemptsExhausted { attempts: 3, .. }
    ));
    assert_eq!(transport.real_calls.load(Ordering::SeqCst), 3);
    client.stop();
}
