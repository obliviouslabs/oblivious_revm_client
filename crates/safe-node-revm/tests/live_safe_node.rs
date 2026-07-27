#![cfg(not(target_arch = "wasm32"))]

use safe_node_revm::{
    Address, B256, BlockSelector, Bytes, NativeClientConfig, PinnedHttpTransport, RateClient,
    SEPOLIA_WETH9_FIXTURE, SchedulerConfig, U256,
};
use serde::Deserialize;
use std::{env, sync::Arc, time::Duration};

const DEFAULT_RPC_URL: &str = "https://rpc-gcp.safe-node.com/olabs-api-6f66df6d6bd1669ed0b2c3c4b2ef8e4307b334b8be7a2f3f6dcae10ada44f82b/json_rpc";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Fixture {
    block: String,
    state_root: B256,
    address: Address,
    slot: U256,
    expected_value: U256,
    #[allow(dead_code)]
    code: Bytes,
}

#[test]
fn dev_safe_node_returns_an_authenticated_proof() {
    if env::var("SAFE_NODE_INTEGRATION").as_deref() != Ok("1") {
        eprintln!("skipped: set SAFE_NODE_INTEGRATION=1 after first-contact attestation");
        return;
    }
    let pin = env::var("SAFE_NODE_TLS_PIN")
        .expect("SAFE_NODE_TLS_PIN must come from a successful safe-revm attest run");
    let rpc_url = env::var("SAFE_NODE_RPC_URL").unwrap_or_else(|_| DEFAULT_RPC_URL.to_owned());
    let tls_domain =
        env::var("SAFE_NODE_TLS_DOMAIN").unwrap_or_else(|_| "rpc-gcp.safe-node.com".to_owned());
    let fixture: Fixture = serde_json::from_str(SEPOLIA_WETH9_FIXTURE).unwrap();
    let block = u64::from_str_radix(fixture.block.trim_start_matches("0x"), 16).unwrap();

    let transport = Arc::new(
        PinnedHttpTransport::new(rpc_url, tls_domain, &pin, Duration::from_secs(30)).unwrap(),
    );
    let client = RateClient::start(
        NativeClientConfig {
            scheduler: SchedulerConfig {
                block: BlockSelector::Number(block),
                storage_keys_per_request: 1,
                dummy_address: fixture.address,
                dummy_slot: fixture.slot,
            },
            state_root: fixture.state_root,
            requests_per_second: 4,
            max_attempts: 10,
        },
        transport,
    )
    .unwrap();

    let proof = client.get_proof(fixture.address, &[fixture.slot]).unwrap();
    assert!(proof.account.is_some());
    assert_eq!(proof.storage, vec![(fixture.slot, fixture.expected_value)]);
    client.stop();
}
