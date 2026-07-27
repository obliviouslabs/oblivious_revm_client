#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Safe Node `eth_getProof` support for `revm`.
//!
//! The target-neutral pieces are request/response types, MPT verification, the
//! deterministic cadence scheduler, and cache/preload handling. Native builds
//! additionally expose the HTTP transport and blocking `revm::Database` adapter.

/// Immutable Sepolia WETH9 fixture used by examples and offline tests.
pub const SEPOLIA_WETH9_FIXTURE: &str = include_str!("../fixtures/sepolia-weth9-11344323.json");

mod proof;
mod rpc;
mod scheduler;
mod state;

#[cfg(not(target_arch = "wasm32"))]
mod native;

pub use proof::{ProofError, VerifiedAccount, VerifiedProof, verify_response};
pub use rpc::{
    BlockSelector, GetProofResponse, JsonRpcError, JsonRpcRequest, JsonRpcResponse, StorageProof,
};
pub use scheduler::{
    CadenceClass, ConstantRateScheduler, PendingRequest, ScheduledRequest, SchedulerConfig,
    SchedulerError,
};
pub use state::{CacheError, ProofCache, Query};

#[cfg(not(target_arch = "wasm32"))]
pub use native::{
    NativeClientConfig, PinnedHttpTransport, RateClient, RpcTransport, SafeNodeDb, SafeNodeError,
    TransportError,
};

pub use alloy_primitives::{Address, B256, Bytes, U256};
pub use revm::state::{AccountInfo, Bytecode};
