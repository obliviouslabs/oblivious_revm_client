#![forbid(unsafe_code)]

//! Browser wrapper that makes synchronous `revm::Database` misses replayable.
//!
//! Browser I/O cannot block a synchronous WebAssembly call. Each attempt either
//! completes or returns one missing query. JavaScript submits that query through
//! the constant-rate KPS queue, applies the authenticated proof, and retries the
//! execution from a clean EVM journal. The authenticated cache survives retries.

use revm::{
    Context, ExecuteEvm, MainBuilder, MainContext,
    context::TxEnv,
    context_interface::result::{EVMError, ExecutionResult, Output},
    database_interface::{DBErrorMarker, Database},
    primitives::{StorageKey, StorageValue, TxKind},
    state::{AccountInfo, Bytecode},
};
use safe_node_revm::{
    Address, B256, BlockSelector, Bytes, JsonRpcRequest, JsonRpcResponse, ProofCache, Query, U256,
    verify_response,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use wasm_bindgen::prelude::*;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct ExecutorConfig {
    state_root: B256,
    block: String,
    contract: Address,
    bytecode: Bytes,
    calldata: Bytes,
    dummy_address: Address,
    dummy_slot: U256,
    #[serde(default = "default_storage_width")]
    storage_keys_per_request: usize,
    #[serde(default = "default_max_attempts")]
    max_attempts: u8,
}

const fn default_storage_width() -> usize {
    1
}

const fn default_max_attempts() -> u8 {
    10
}

#[derive(Serialize)]
#[serde(tag = "status", rename_all = "camelCase")]
enum AttemptResult {
    Need {
        query: Query,
        attempt: u8,
        max_attempts: u8,
    },
    Success {
        output: String,
        attempt: u8,
    },
    Revert {
        output: String,
        attempt: u8,
    },
    Failure {
        message: String,
        attempt: u8,
    },
}

#[derive(Debug, Error)]
enum ReplayDbError {
    #[error("database value is not cached")]
    Pending(Query),
    #[error("cache error: {0}")]
    Cache(String),
    #[error("bytecode {0:#x} was not preloaded")]
    MissingBytecode(B256),
    #[error("BLOCKHASH {0} was not preloaded")]
    MissingBlockHash(u64),
}

impl DBErrorMarker for ReplayDbError {}

#[derive(Debug, Default)]
struct ReplayDb {
    cache: ProofCache,
}

impl Database for ReplayDb {
    type Error = ReplayDbError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        self.cache
            .account_info(address)
            .map_err(|error| ReplayDbError::Cache(error.to_string()))?
            .ok_or(ReplayDbError::Pending(Query::Account { address }))
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.cache
            .bytecode(code_hash)
            .ok_or(ReplayDbError::MissingBytecode(code_hash))
    }

    fn storage(
        &mut self,
        address: Address,
        index: StorageKey,
    ) -> Result<StorageValue, Self::Error> {
        self.cache
            .storage(address, index)
            .ok_or(ReplayDbError::Pending(Query::Storage {
                address,
                slot: index,
            }))
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.cache
            .block_hash(number)
            .ok_or(ReplayDbError::MissingBlockHash(number))
    }
}

/// Replayable browser EVM state machine.
#[wasm_bindgen]
pub struct WasmExecutor {
    db: ReplayDb,
    state_root: B256,
    block: BlockSelector,
    block_number: u64,
    contract: Address,
    caller: Address,
    calldata: Bytes,
    dummy_address: Address,
    dummy_slot: U256,
    storage_width: usize,
    attempts: u8,
    max_attempts: u8,
}

#[wasm_bindgen]
impl WasmExecutor {
    /// Construct from a JSON object. All state is anchored to one immutable
    /// block and trusted state root.
    #[wasm_bindgen(constructor)]
    pub fn new(config_json: &str) -> Result<WasmExecutor, JsValue> {
        let config: ExecutorConfig = serde_json::from_str(config_json).map_err(js_error)?;
        if config.storage_keys_per_request == 0 {
            return Err(JsValue::from_str(
                "storageKeysPerRequest must be greater than zero",
            ));
        }
        if !(1..=10).contains(&config.max_attempts) {
            return Err(JsValue::from_str("maxAttempts must be between 1 and 10"));
        }
        let block = parse_quantity_u64(&config.block)
            .map_err(|error| JsValue::from_str(&format!("invalid block: {error}")))?;
        let caller = Address::repeat_byte(0x11);
        let mut db = ReplayDb::default();
        db.cache
            .preload_bytecode_at(config.contract, config.bytecode);
        db.cache
            .preload_local_account(caller, AccountInfo::default().with_balance(U256::MAX));
        db.cache
            .preload_local_account(Address::ZERO, AccountInfo::default());

        Ok(Self {
            db,
            state_root: config.state_root,
            block: BlockSelector::Number(block),
            block_number: block,
            contract: config.contract,
            caller,
            calldata: config.calldata,
            dummy_address: config.dummy_address,
            dummy_slot: config.dummy_slot,
            storage_width: config.storage_keys_per_request,
            attempts: 0,
            max_attempts: config.max_attempts,
        })
    }

    /// Run one clean-journal attempt and return JSON describing success, a
    /// missing query, or a terminal error.
    #[wasm_bindgen(js_name = executeAttempt)]
    pub fn execute_attempt(&mut self) -> String {
        if self.attempts >= self.max_attempts {
            return json(&AttemptResult::Failure {
                message: format!(
                    "execution did not complete within {} replay attempts",
                    self.max_attempts
                ),
                attempt: self.attempts,
            });
        }
        self.attempts += 1;
        let block_number = self.block_number;
        let mut evm = Context::mainnet()
            .with_db(&mut self.db)
            .modify_block_chained(|block_env| {
                block_env.number = U256::from(block_number);
            })
            .modify_cfg_chained(|cfg| cfg.chain_id = 11_155_111)
            .build_mainnet();
        let tx = match TxEnv::builder()
            .caller(self.caller)
            .kind(TxKind::Call(self.contract))
            .data(self.calldata.clone())
            .gas_limit(1_000_000)
            .chain_id(Some(11_155_111))
            .build()
        {
            Ok(tx) => tx,
            Err(error) => {
                return json(&AttemptResult::Failure {
                    message: error.to_string(),
                    attempt: self.attempts,
                });
            }
        };

        match evm.transact_one(tx) {
            Err(EVMError::Database(ReplayDbError::Pending(query))) => json(&AttemptResult::Need {
                query,
                attempt: self.attempts,
                max_attempts: self.max_attempts,
            }),
            Err(error) => json(&AttemptResult::Failure {
                message: error.to_string(),
                attempt: self.attempts,
            }),
            Ok(ExecutionResult::Success {
                output: Output::Call(output),
                ..
            }) => json(&AttemptResult::Success {
                output: fixed_bytes(&output),
                attempt: self.attempts,
            }),
            Ok(ExecutionResult::Revert { output, .. }) => json(&AttemptResult::Revert {
                output: fixed_bytes(&output),
                attempt: self.attempts,
            }),
            Ok(other) => json(&AttemptResult::Failure {
                message: format!("EVM halted: {other:?}"),
                attempt: self.attempts,
            }),
        }
    }

    /// Build the exact fixed-shape JSON-RPC request for one real query.
    #[wasm_bindgen(js_name = requestFor)]
    pub fn request_for(&self, query_json: &str, id: &str) -> Result<String, JsValue> {
        let query: Query = serde_json::from_str(query_json).map_err(js_error)?;
        let (address, slots) = self.shape_query(&query);
        serde_json::to_string(&JsonRpcRequest::get_proof(
            fixed_id(id)?,
            address,
            &slots,
            self.block.clone(),
        ))
        .map_err(js_error)
    }

    /// Build account or storage cover traffic with the same public class shape.
    #[wasm_bindgen(js_name = coverRequest)]
    pub fn cover_request(&self, storage: bool, id: &str) -> Result<String, JsValue> {
        let slots = if storage {
            vec![self.dummy_slot; self.storage_width]
        } else {
            Vec::new()
        };
        serde_json::to_string(&JsonRpcRequest::get_proof(
            fixed_id(id)?,
            self.dummy_address,
            &slots,
            self.block.clone(),
        ))
        .map_err(js_error)
    }

    /// Verify and cache a real response. JSON-RPC errors are returned to
    /// JavaScript so its queue can retry only on a later matching tick.
    #[wasm_bindgen(js_name = applyProof)]
    pub fn apply_proof(&mut self, query_json: &str, response_json: &str) -> Result<(), JsValue> {
        let query: Query = serde_json::from_str(query_json).map_err(js_error)?;
        let envelope = JsonRpcResponse::parse(response_json).map_err(js_error)?;
        if let Some(error) = envelope.error {
            return Err(JsValue::from_str(&format!(
                "JSON-RPC {}: {}",
                error.code, error.message
            )));
        }
        let response = envelope
            .result
            .ok_or_else(|| JsValue::from_str("response has neither result nor error"))?;
        let (address, sent_slots) = self.shape_query(&query);
        let real_slots = match query {
            Query::Account { .. } => Vec::new(),
            Query::Storage { slot, .. } => vec![slot],
        };
        let proof =
            verify_response(self.state_root, address, &sent_slots, &response).map_err(js_error)?;
        self.db
            .cache
            .apply_verified(address, &real_slots, proof)
            .map_err(js_error)
    }

    /// Number of EVM replay attempts already consumed.
    #[wasm_bindgen(getter)]
    pub fn attempts(&self) -> u8 {
        self.attempts
    }
}

impl WasmExecutor {
    fn shape_query(&self, query: &Query) -> (Address, Vec<U256>) {
        match query {
            Query::Account { address } => (*address, Vec::new()),
            Query::Storage { address, slot } => (*address, vec![*slot; self.storage_width]),
        }
    }
}

fn parse_quantity_u64(value: &str) -> Result<u64, std::num::ParseIntError> {
    u64::from_str_radix(value.strip_prefix("0x").unwrap_or(value), 16)
}

fn fixed_id(id: &str) -> Result<String, JsValue> {
    if !id.is_ascii() || !id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(JsValue::from_str(
            "JSON-RPC id must contain only ASCII hex digits",
        ));
    }
    let value = if id.len() > 16 {
        &id[id.len() - 16..]
    } else {
        id
    };
    Ok(format!("{value:0>16}"))
}

fn fixed_bytes(bytes: &[u8]) -> String {
    format!(
        "0x{}",
        bytes
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    )
}

fn json(value: &AttemptResult) -> String {
    serde_json::to_string(value).expect("attempt result serialization cannot fail")
}

fn js_error(error: impl std::fmt::Display) -> JsValue {
    JsValue::from_str(&error.to_string())
}
