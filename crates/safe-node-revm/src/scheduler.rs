use crate::rpc::{BlockSelector, JsonRpcRequest};
use alloy_primitives::{Address, U256};
use std::collections::VecDeque;
use thiserror::Error;

/// Public, input-independent tick class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CadenceClass {
    /// Account proof with no storage keys.
    Account,
    /// Proof with exactly the configured number of storage keys.
    Storage,
}

/// Deterministic scheduler settings.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerConfig {
    /// Immutable block selector shared by real and dummy calls.
    pub block: BlockSelector,
    /// Number of storage-key entries on every storage tick.
    pub storage_keys_per_request: usize,
    /// Cover account. A frequently accessed contract at the anchored block is
    /// preferable to a random address that could enter Safe Node's missing-node path.
    pub dummy_address: Address,
    /// Cover storage key. It is repeated, avoiding extra proof paths.
    pub dummy_slot: U256,
}

impl SchedulerConfig {
    /// Validate scheduler settings.
    pub fn validate(&self) -> Result<(), SchedulerError> {
        if self.storage_keys_per_request == 0 {
            return Err(SchedulerError::ZeroStorageKeys);
        }
        Ok(())
    }
}

/// Application work waiting to replace a cover request.
#[derive(Clone, Debug)]
pub struct PendingRequest<T> {
    /// Account to prove.
    pub address: Address,
    /// Real, unpadded storage keys. Empty means an account-only request.
    pub storage_keys: Vec<U256>,
    /// Caller-owned correlation data.
    pub context: T,
    /// One-based transmission attempt number.
    pub attempt: u8,
}

impl<T> PendingRequest<T> {
    /// Create account-only work.
    pub fn account(address: Address, context: T) -> Self {
        Self {
            address,
            storage_keys: Vec::new(),
            context,
            attempt: 1,
        }
    }

    /// Create storage work. Splitting is performed by
    /// [`ConstantRateScheduler::enqueue`]. An empty key list is treated as an
    /// account-only request.
    pub fn storage(address: Address, storage_keys: Vec<U256>, context: T) -> Self {
        Self {
            address,
            storage_keys,
            context,
            attempt: 1,
        }
    }
}

/// One request selected for a deterministic tick.
#[derive(Clone, Debug)]
pub struct ScheduledRequest<T> {
    /// Predetermined request class.
    pub class: CadenceClass,
    /// Wire request.
    pub rpc: JsonRpcRequest,
    /// Real work, or `None` for cover traffic.
    pub real: Option<PendingRequest<T>>,
    /// Exact keys sent on the wire, including repeated padding.
    pub sent_storage_keys: Vec<U256>,
}

/// Scheduler configuration or enqueue error.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SchedulerError {
    /// A storage cadence cannot have zero entries.
    #[error("storage_keys_per_request must be greater than zero")]
    ZeroStorageKeys,
}

/// Pure deterministic real-or-cover scheduler.
///
/// Calls to [`tick`](Self::tick) alternate account and storage classes. Wall
/// clock policy is deliberately outside this type so tests can use exact,
/// deterministic ticks and native/browser runtimes can provide their own timer.
#[derive(Debug)]
pub struct ConstantRateScheduler<T> {
    config: SchedulerConfig,
    account_queue: VecDeque<PendingRequest<T>>,
    storage_queue: VecDeque<PendingRequest<T>>,
    next_class: CadenceClass,
    next_id: u64,
}

impl<T> ConstantRateScheduler<T> {
    /// Create an empty scheduler.
    pub fn new(config: SchedulerConfig) -> Result<Self, SchedulerError> {
        config.validate()?;
        Ok(Self {
            config,
            account_queue: VecDeque::new(),
            storage_queue: VecDeque::new(),
            next_class: CadenceClass::Account,
            next_id: 0,
        })
    }

    /// Scheduler settings.
    pub fn config(&self) -> &SchedulerConfig {
        &self.config
    }

    /// Number of queued real chunks.
    pub fn queued_len(&self) -> usize {
        self.account_queue.len() + self.storage_queue.len()
    }

    /// Enqueue work, splitting storage keys into fixed-capacity chunks.
    ///
    /// A cloned context is attached to every chunk. The caller can aggregate
    /// chunk results using that context and the real key list.
    pub fn enqueue(&mut self, request: PendingRequest<T>) -> Result<usize, SchedulerError>
    where
        T: Clone,
    {
        if request.storage_keys.is_empty() {
            self.account_queue.push_back(request);
            return Ok(1);
        }

        let width = self.config.storage_keys_per_request;
        let mut chunks = 0;
        for keys in request.storage_keys.chunks(width) {
            self.storage_queue.push_back(PendingRequest {
                address: request.address,
                storage_keys: keys.to_vec(),
                context: request.context.clone(),
                attempt: request.attempt,
            });
            chunks += 1;
        }
        Ok(chunks)
    }

    /// Requeue a failed real request at the front of its matching class.
    pub fn retry(&mut self, mut request: PendingRequest<T>) {
        request.attempt = request.attempt.saturating_add(1);
        if request.storage_keys.is_empty() {
            self.account_queue.push_front(request);
        } else {
            self.storage_queue.push_front(request);
        }
    }

    /// Produce exactly one real-or-cover wire request.
    pub fn tick(&mut self) -> ScheduledRequest<T> {
        let class = self.next_class;
        self.next_class = match class {
            CadenceClass::Account => CadenceClass::Storage,
            CadenceClass::Storage => CadenceClass::Account,
        };
        self.next_id = self.next_id.wrapping_add(1);
        let id = format!("{:016x}", self.next_id);

        match class {
            CadenceClass::Account => {
                let real = self.account_queue.pop_front();
                let address = real
                    .as_ref()
                    .map_or(self.config.dummy_address, |request| request.address);
                ScheduledRequest {
                    class,
                    rpc: JsonRpcRequest::get_proof(id, address, &[], self.config.block.clone()),
                    real,
                    sent_storage_keys: Vec::new(),
                }
            }
            CadenceClass::Storage => {
                let real = self.storage_queue.pop_front();
                let (address, keys) = match &real {
                    Some(request) => {
                        let mut padded = request.storage_keys.clone();
                        let padding = *padded
                            .last()
                            .expect("storage queue only contains non-empty requests");
                        padded.resize(self.config.storage_keys_per_request, padding);
                        (request.address, padded)
                    }
                    None => (
                        self.config.dummy_address,
                        vec![self.config.dummy_slot; self.config.storage_keys_per_request],
                    ),
                };
                ScheduledRequest {
                    class,
                    rpc: JsonRpcRequest::get_proof(id, address, &keys, self.config.block.clone()),
                    real,
                    sent_storage_keys: keys,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{Address, U256};

    fn config(width: usize) -> SchedulerConfig {
        SchedulerConfig {
            block: BlockSelector::Number(1),
            storage_keys_per_request: width,
            dummy_address: Address::ZERO,
            dummy_slot: U256::ZERO,
        }
    }

    #[test]
    fn deterministic_ticks_always_emit_one_request() {
        let mut scheduler = ConstantRateScheduler::<u64>::new(config(2)).unwrap();
        let ticks: Vec<_> = (0..10).map(|_| scheduler.tick()).collect();
        assert_eq!(ticks.len(), 10);
        for (index, tick) in ticks.iter().enumerate() {
            let expected = if index % 2 == 0 {
                CadenceClass::Account
            } else {
                CadenceClass::Storage
            };
            assert_eq!(tick.class, expected);
            assert!(tick.real.is_none());
        }
    }

    #[test]
    fn real_requests_replace_cover_without_changing_tick_count() {
        let mut baseline = ConstantRateScheduler::<u64>::new(config(1)).unwrap();
        let baseline_count = (0..8).map(|_| baseline.tick()).count();

        let mut scheduler = ConstantRateScheduler::new(config(1)).unwrap();
        scheduler
            .enqueue(PendingRequest::account(Address::repeat_byte(1), 7_u64))
            .unwrap();
        scheduler
            .enqueue(PendingRequest::storage(
                Address::repeat_byte(2),
                vec![U256::from(9)],
                8_u64,
            ))
            .unwrap();
        let ticks: Vec<_> = (0..8).map(|_| scheduler.tick()).collect();

        assert_eq!(ticks.len(), baseline_count);
        assert_eq!(ticks.iter().filter(|tick| tick.real.is_some()).count(), 2);
        assert_eq!(ticks[0].real.as_ref().unwrap().context, 7);
        assert_eq!(ticks[1].real.as_ref().unwrap().context, 8);
    }

    #[test]
    fn splits_and_pads_to_fixed_storage_width() {
        let mut scheduler = ConstantRateScheduler::new(config(3)).unwrap();
        let slots = (1..=7).map(U256::from).collect();
        let chunks = scheduler
            .enqueue(PendingRequest::storage(Address::repeat_byte(3), slots, ()))
            .unwrap();
        assert_eq!(chunks, 3);

        // Skip account ticks and inspect the three storage ticks.
        let mut sent = Vec::new();
        for _ in 0..3 {
            assert_eq!(scheduler.tick().class, CadenceClass::Account);
            let storage = scheduler.tick();
            assert_eq!(storage.sent_storage_keys.len(), 3);
            sent.push(storage.sent_storage_keys);
        }
        assert_eq!(sent[0], vec![U256::from(1), U256::from(2), U256::from(3)]);
        assert_eq!(sent[1], vec![U256::from(4), U256::from(5), U256::from(6)]);
        assert_eq!(sent[2], vec![U256::from(7); 3]);
    }

    #[test]
    fn retry_waits_for_a_future_matching_tick() {
        let mut scheduler = ConstantRateScheduler::new(config(1)).unwrap();
        let request = PendingRequest::storage(Address::repeat_byte(4), vec![U256::from(1)], 5_u64);
        scheduler.enqueue(request).unwrap();
        scheduler.tick();
        let first = scheduler.tick().real.unwrap();
        assert_eq!(first.attempt, 1);
        scheduler.retry(first);
        scheduler.tick();
        let second = scheduler.tick().real.unwrap();
        assert_eq!(second.attempt, 2);
    }
}
