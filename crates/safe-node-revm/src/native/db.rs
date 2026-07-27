use super::worker::{RateClient, SafeNodeError};
use crate::ProofCache;
use alloy_primitives::{Address, B256, Bytes};
use revm::{
    database_interface::Database,
    primitives::{StorageKey, StorageValue},
    state::{AccountInfo, Bytecode},
};
use std::sync::Arc;

/// Synchronous `revm::Database` backed by the dedicated scheduled worker.
#[derive(Debug)]
pub struct SafeNodeDb {
    client: Arc<RateClient>,
    cache: ProofCache,
}

impl SafeNodeDb {
    /// Create an empty authenticated cache.
    pub fn new(client: Arc<RateClient>) -> Self {
        Self {
            client,
            cache: ProofCache::default(),
        }
    }

    /// Access preload/cache controls.
    pub fn cache(&self) -> &ProofCache {
        &self.cache
    }

    /// Access preload/cache controls mutably.
    pub fn cache_mut(&mut self) -> &mut ProofCache {
        &mut self.cache
    }

    /// Preload bytecode at an address and by its computed code hash.
    pub fn preload_bytecode_at(&mut self, address: Address, bytes: Bytes) -> B256 {
        self.cache.preload_bytecode_at(address, bytes)
    }

    /// Preload a simulation-only local account, commonly the transaction caller.
    pub fn preload_local_account(&mut self, address: Address, account: AccountInfo) {
        self.cache.preload_local_account(address, account);
    }

    /// Preload a block hash for contracts that execute `BLOCKHASH`.
    pub fn preload_block_hash(&mut self, number: u64, hash: B256) {
        self.cache.preload_block_hash(number, hash);
    }
}

impl Database for SafeNodeDb {
    type Error = SafeNodeError;

    fn basic(&mut self, address: Address) -> Result<Option<AccountInfo>, Self::Error> {
        if let Some(account) = self.cache.account_info(address)? {
            return Ok(account);
        }
        let proof = self.client.get_proof(address, &[])?;
        self.cache.apply_verified(address, &[], proof)?;
        self.cache
            .account_info(address)?
            .ok_or(SafeNodeError::WorkerStopped)
    }

    fn code_by_hash(&mut self, code_hash: B256) -> Result<Bytecode, Self::Error> {
        self.cache
            .bytecode(code_hash)
            .ok_or(SafeNodeError::MissingBytecode(code_hash))
    }

    fn storage(
        &mut self,
        address: Address,
        index: StorageKey,
    ) -> Result<StorageValue, Self::Error> {
        if let Some(value) = self.cache.storage(address, index) {
            return Ok(value);
        }
        let proof = self.client.get_proof(address, &[index])?;
        self.cache.apply_verified(address, &[index], proof)?;
        self.cache
            .storage(address, index)
            .ok_or(SafeNodeError::WorkerStopped)
    }

    fn block_hash(&mut self, number: u64) -> Result<B256, Self::Error> {
        self.cache
            .block_hash(number)
            .ok_or(SafeNodeError::MissingBlockHash(number))
    }
}
