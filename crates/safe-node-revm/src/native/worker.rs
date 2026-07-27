use super::transport::{RpcTransport, TransportError};
use crate::{
    CacheError, ConstantRateScheduler, JsonRpcResponse, PendingRequest, ProofError,
    ScheduledRequest, SchedulerConfig, VerifiedAccount, VerifiedProof, verify_response,
};
use alloy_primitives::{Address, B256, U256};
use revm::database_interface::DBErrorMarker;
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread::JoinHandle,
    time::Duration,
};
use thiserror::Error;
use tokio::{runtime::Runtime, sync::mpsc as tokio_mpsc, time::MissedTickBehavior};

/// Native constant-rate client settings.
#[derive(Clone, Debug)]
pub struct NativeClientConfig {
    /// Pure scheduler configuration.
    pub scheduler: SchedulerConfig,
    /// Trusted state root for the scheduler's immutable block.
    pub state_root: B256,
    /// Total JSON-RPC calls per second. Account and storage classes alternate.
    pub requests_per_second: u32,
    /// Maximum scheduled transmissions for transient failures, from 1 through 10.
    pub max_attempts: u8,
}

/// Adapter/worker error.
#[derive(Debug, Error)]
pub enum SafeNodeError {
    /// Invalid worker configuration.
    #[error("invalid client configuration: {0}")]
    Config(String),
    /// Scheduled network failure.
    #[error(transparent)]
    Transport(#[from] TransportError),
    /// JSON-RPC application error.
    #[error("Safe Node JSON-RPC error {code}: {message}")]
    Rpc {
        /// Error code.
        code: i64,
        /// Error message.
        message: String,
    },
    /// A transient operation failed on every allowed scheduled attempt.
    #[error("request failed after {attempts} scheduled attempts: {last_error}")]
    AttemptsExhausted {
        /// Number attempted.
        attempts: u8,
        /// Last failure.
        last_error: String,
    },
    /// Cryptographic proof verification failed. This is never retried silently.
    #[error(transparent)]
    Proof(#[from] ProofError),
    /// Authenticated responses or preloads were inconsistent.
    #[error(transparent)]
    Cache(#[from] CacheError),
    /// Request/response identifiers did not match.
    #[error("JSON-RPC response id mismatch")]
    ResponseId,
    /// The worker is no longer accepting work.
    #[error("constant-rate request worker stopped")]
    WorkerStopped,
    /// Safe Node does not serve code and no matching preload exists.
    #[error("bytecode {0:#x} was not preloaded; Safe Node does not expose private eth_getCode")]
    MissingBytecode(B256),
    /// Safe Node does not expose block headers and this hash was not preloaded.
    #[error("block hash for number {0} was not preloaded")]
    MissingBlockHash(u64),
    /// Multiple chunks at one state root disagreed about the account.
    #[error("proof chunks disagreed about account fields")]
    ChunkAccountMismatch,
}

impl DBErrorMarker for SafeNodeError {}

#[derive(Clone, Debug)]
struct JobContext {
    index: usize,
    completion: mpsc::Sender<Result<ChunkResult, SafeNodeError>>,
}

#[derive(Debug)]
struct ChunkResult {
    index: usize,
    proof: VerifiedProof,
}

type Command = PendingRequest<JobContext>;

type Completion = (
    ScheduledRequest<JobContext>,
    Result<JsonRpcResponse, TransportError>,
);

/// Handle to a dedicated constant-rate worker.
#[derive(Debug)]
pub struct RateClient {
    command_tx: mpsc::Sender<Command>,
    shutdown: Arc<AtomicBool>,
    pin_mismatch: Arc<AtomicBool>,
    join: Mutex<Option<JoinHandle<()>>>,
    storage_width: usize,
}

impl RateClient {
    /// Start the worker. Its cadence continues until all handles are dropped or
    /// [`stop`](Self::stop) is called explicitly.
    pub fn start(
        config: NativeClientConfig,
        transport: Arc<dyn RpcTransport>,
    ) -> Result<Arc<Self>, SafeNodeError> {
        config
            .scheduler
            .validate()
            .map_err(|error| SafeNodeError::Config(error.to_string()))?;
        if config.requests_per_second == 0 {
            return Err(SafeNodeError::Config(
                "requests_per_second must be greater than zero".to_owned(),
            ));
        }
        if !(1..=10).contains(&config.max_attempts) {
            return Err(SafeNodeError::Config(
                "max_attempts must be between 1 and 10".to_owned(),
            ));
        }
        let period_nanos = 1_000_000_000_u64 / u64::from(config.requests_per_second);
        if period_nanos == 0 {
            return Err(SafeNodeError::Config(
                "requests_per_second is too high".to_owned(),
            ));
        }

        let runtime = Runtime::new().map_err(|error| SafeNodeError::Config(error.to_string()))?;
        let storage_width = config.scheduler.storage_keys_per_request;
        let (command_tx, command_rx) = mpsc::channel();
        let shutdown = Arc::new(AtomicBool::new(false));
        let worker_shutdown = shutdown.clone();
        let pin_mismatch = Arc::new(AtomicBool::new(false));
        let worker_pin_mismatch = pin_mismatch.clone();
        let join = std::thread::Builder::new()
            .name("safe-node-constant-rate".to_owned())
            .spawn(move || {
                runtime.block_on(run_worker(
                    config,
                    transport,
                    command_rx,
                    worker_shutdown,
                    worker_pin_mismatch,
                    Duration::from_nanos(period_nanos),
                ));
            })
            .map_err(|error| SafeNodeError::Config(error.to_string()))?;

        Ok(Arc::new(Self {
            command_tx,
            shutdown,
            pin_mismatch,
            join: Mutex::new(Some(join)),
            storage_width,
        }))
    }

    /// Resolve an account and zero or more storage slots. Larger key sets are
    /// split before entering the scheduler and aggregated by original order.
    pub fn get_proof(
        &self,
        address: Address,
        storage_keys: &[U256],
    ) -> Result<VerifiedProof, SafeNodeError> {
        if self.pin_mismatch.load(Ordering::Acquire) {
            return Err(SafeNodeError::Transport(TransportError::PinMismatch));
        }
        let chunks: Vec<Vec<U256>> = if storage_keys.is_empty() {
            vec![Vec::new()]
        } else {
            storage_keys
                .chunks(self.storage_width)
                .map(<[U256]>::to_vec)
                .collect()
        };
        let (completion, receiver) = mpsc::channel();
        for (index, keys) in chunks.iter().cloned().enumerate() {
            let context = JobContext {
                index,
                completion: completion.clone(),
            };
            let command = if keys.is_empty() {
                PendingRequest::account(address, context)
            } else {
                PendingRequest::storage(address, keys, context)
            };
            self.command_tx
                .send(command)
                .map_err(|_| self.inactive_error())?;
        }
        drop(completion);

        let mut ordered: Vec<Option<VerifiedProof>> = vec![None; chunks.len()];
        for _ in 0..chunks.len() {
            let result = receiver.recv().map_err(|_| self.inactive_error())??;
            ordered[result.index] = Some(result.proof);
        }

        let mut account: Option<Option<VerifiedAccount>> = None;
        let mut storage = Vec::with_capacity(storage_keys.len());
        for proof in ordered.into_iter().flatten() {
            match &account {
                Some(previous) if previous != &proof.account => {
                    return Err(SafeNodeError::ChunkAccountMismatch);
                }
                None => account = Some(proof.account.clone()),
                _ => {}
            }
            storage.extend(proof.storage);
        }
        Ok(VerifiedProof {
            account: account.flatten(),
            storage,
        })
    }

    /// Stop cover traffic. Prefer an application-defined cover window over
    /// calling this immediately after a sensitive execution.
    pub fn stop(&self) {
        self.shutdown.store(true, Ordering::Release);
    }

    fn inactive_error(&self) -> SafeNodeError {
        if self.pin_mismatch.load(Ordering::Acquire) {
            SafeNodeError::Transport(TransportError::PinMismatch)
        } else {
            SafeNodeError::WorkerStopped
        }
    }
}

impl Drop for RateClient {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Release);
        if let Some(join) = self.join.lock().expect("worker join mutex poisoned").take() {
            let _ = join.join();
        }
    }
}

async fn run_worker(
    config: NativeClientConfig,
    transport: Arc<dyn RpcTransport>,
    command_rx: mpsc::Receiver<Command>,
    shutdown: Arc<AtomicBool>,
    pin_mismatch: Arc<AtomicBool>,
    period: Duration,
) {
    let mut scheduler = match ConstantRateScheduler::new(config.scheduler.clone()) {
        Ok(scheduler) => scheduler,
        Err(_) => return,
    };
    let (completion_tx, mut completion_rx) = tokio_mpsc::unbounded_channel::<Completion>();
    let start = tokio::time::Instant::now() + period;
    let mut ticker = tokio::time::interval_at(start, period);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Skip);

    while !shutdown.load(Ordering::Acquire) {
        while let Ok(command) = command_rx.try_recv() {
            // Commands are pre-split, so this always creates one queue item.
            let _ = scheduler.enqueue(command);
        }

        tokio::select! {
            _ = ticker.tick() => {
                while let Ok(command) = command_rx.try_recv() {
                    let _ = scheduler.enqueue(command);
                }
                let scheduled = scheduler.tick();
                let rpc = scheduled.rpc.clone();
                let transport = transport.clone();
                let completion_tx = completion_tx.clone();
                tokio::spawn(async move {
                    let result = transport.send(rpc).await;
                    let _ = completion_tx.send((scheduled, result));
                });
            }
            Some((scheduled, result)) = completion_rx.recv() => {
                if handle_completion(
                    &config,
                    &mut scheduler,
                    scheduled,
                    result,
                ) {
                    pin_mismatch.store(true, Ordering::Release);
                    shutdown.store(true, Ordering::Release);
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(25)) => {}
        }
    }
}

/// Handle one completion and report whether the worker must stop permanently.
fn handle_completion(
    config: &NativeClientConfig,
    scheduler: &mut ConstantRateScheduler<JobContext>,
    scheduled: ScheduledRequest<JobContext>,
    result: Result<JsonRpcResponse, TransportError>,
) -> bool {
    let result = match result {
        Err(TransportError::PinMismatch) => {
            if let Some(real) = &scheduled.real {
                send_error(real, SafeNodeError::Transport(TransportError::PinMismatch));
            }
            // A mismatch on either real or cover traffic invalidates the
            // transport identity. Stop all traffic until first contact is run
            // again instead of continuously probing with a stale pin.
            return true;
        }
        other => other,
    };

    let Some(real) = scheduled.real else {
        // Cover responses are deliberately not allowed to enqueue work or alter cadence.
        return false;
    };

    let failure = match result {
        Err(error) => Some(error.to_string()),
        Ok(response) => {
            if response.id != serde_json::Value::String(scheduled.rpc.id.clone()) {
                send_error(&real, SafeNodeError::ResponseId);
                return false;
            }
            if let Some(error) = response.error {
                if error.code == -32001 {
                    Some(format!("JSON-RPC {}: {}", error.code, error.message))
                } else {
                    send_error(
                        &real,
                        SafeNodeError::Rpc {
                            code: error.code,
                            message: error.message,
                        },
                    );
                    return false;
                }
            } else if let Some(response) = response.result {
                match verify_response(
                    config.state_root,
                    real.address,
                    &scheduled.sent_storage_keys,
                    &response,
                ) {
                    Ok(mut proof) => {
                        proof.storage.truncate(real.storage_keys.len());
                        let _ = real.context.completion.send(Ok(ChunkResult {
                            index: real.context.index,
                            proof,
                        }));
                    }
                    Err(error) => send_error(&real, SafeNodeError::Proof(error)),
                }
                return false;
            } else {
                Some("response has neither result nor error".to_owned())
            }
        }
    };

    if let Some(last_error) = failure {
        if real.attempt < config.max_attempts {
            scheduler.retry(real);
        } else {
            let attempts = real.attempt;
            send_error(
                &real,
                SafeNodeError::AttemptsExhausted {
                    attempts,
                    last_error,
                },
            );
        }
    }
    false
}

fn send_error(request: &PendingRequest<JobContext>, error: SafeNodeError) {
    let _ = request.context.completion.send(Err(error));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::BlockSelector;

    #[test]
    fn pin_mismatch_on_cover_traffic_stops_the_worker() {
        let scheduler_config = SchedulerConfig {
            block: BlockSelector::Number(1),
            storage_keys_per_request: 1,
            dummy_address: Address::ZERO,
            dummy_slot: U256::ZERO,
        };
        let config = NativeClientConfig {
            scheduler: scheduler_config.clone(),
            state_root: B256::ZERO,
            requests_per_second: 1,
            max_attempts: 10,
        };
        let mut scheduler = ConstantRateScheduler::new(scheduler_config).unwrap();
        let cover = scheduler.tick();

        assert!(handle_completion(
            &config,
            &mut scheduler,
            cover,
            Err(TransportError::PinMismatch),
        ));
    }
}
