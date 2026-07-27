use crate::proof::{VerifiedAccount, VerifiedProof};
use alloy_primitives::{Address, B256, Bytes, U256};
use alloy_trie::KECCAK_EMPTY;
use revm::state::{AccountInfo, Bytecode};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;

/// A database miss that an asynchronous host must resolve.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum Query {
    /// Fetch account fields without storage keys.
    Account {
        /// Account address.
        address: Address,
    },
    /// Fetch one storage slot. The scheduler may repeat it for padding.
    Storage {
        /// Account address.
        address: Address,
        /// Unhashed storage slot.
        slot: U256,
    },
}

/// Cache/preload consistency failure.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CacheError {
    /// Two authenticated responses at one state root disagree.
    #[error("authenticated account response changed for {0:#x}")]
    AccountChanged(Address),
    /// Two authenticated responses at one state root disagree.
    #[error("authenticated storage response changed for {address:#x} slot {slot:#x}")]
    StorageChanged {
        /// Account address.
        address: Address,
        /// Storage slot.
        slot: U256,
    },
    /// Authenticated storage entries do not cover the requested real keys.
    #[error("authenticated storage entries do not match the requested keys")]
    StorageShape,
    /// Address-preloaded bytecode does not match the account proof.
    #[error(
        "preloaded bytecode hash mismatch for {address:#x}: got {got:#x}, proof commits {expected:#x}"
    )]
    BytecodeHash {
        /// Contract address.
        address: Address,
        /// Hash of preloaded bytes.
        got: B256,
        /// Hash committed by the account.
        expected: B256,
    },
}

/// Authenticated state cache plus explicitly public/preloaded EVM data.
#[derive(Clone, Debug, Default)]
pub struct ProofCache {
    accounts: HashMap<Address, Option<VerifiedAccount>>,
    storage: HashMap<(Address, U256), U256>,
    bytecodes: HashMap<B256, Bytecode>,
    address_bytecodes: HashMap<Address, (B256, Bytecode)>,
    local_accounts: HashMap<Address, AccountInfo>,
    block_hashes: HashMap<u64, B256>,
}

impl ProofCache {
    /// Insert bytecode indexed by its computed hash.
    pub fn preload_bytecode(&mut self, bytes: Bytes) -> B256 {
        let bytecode = Bytecode::new_raw(bytes);
        let hash = bytecode.hash_slow();
        self.bytecodes.insert(hash, bytecode);
        hash
    }

    /// Insert bytecode for an address and by its computed hash.
    pub fn preload_bytecode_at(&mut self, address: Address, bytes: Bytes) -> B256 {
        let bytecode = Bytecode::new_raw(bytes);
        let hash = bytecode.hash_slow();
        self.bytecodes.insert(hash, bytecode.clone());
        self.address_bytecodes.insert(address, (hash, bytecode));
        hash
    }

    /// Insert a local account that intentionally bypasses Safe Node, such as a
    /// simulation-only transaction caller. This must not be used for private
    /// chain state that should be proof-authenticated.
    pub fn preload_local_account(&mut self, address: Address, account: AccountInfo) {
        self.local_accounts.insert(address, account);
    }

    /// Preload a block hash for contracts using the `BLOCKHASH` opcode.
    pub fn preload_block_hash(&mut self, number: u64, hash: B256) {
        self.block_hashes.insert(number, hash);
    }

    /// Apply an authenticated response. Only real keys are cached; repeated
    /// padding entries are verified but discarded.
    pub fn apply_verified(
        &mut self,
        address: Address,
        real_keys: &[U256],
        proof: VerifiedProof,
    ) -> Result<(), CacheError> {
        if proof.storage.len() < real_keys.len()
            || real_keys
                .iter()
                .zip(&proof.storage)
                .any(|(expected, (actual, _))| expected != actual)
        {
            return Err(CacheError::StorageShape);
        }

        if self
            .accounts
            .get(&address)
            .is_some_and(|previous| previous != &proof.account)
        {
            return Err(CacheError::AccountChanged(address));
        }
        for (slot, value) in proof.storage.iter().take(real_keys.len()) {
            if self
                .storage
                .get(&(address, *slot))
                .is_some_and(|previous| previous != value)
            {
                return Err(CacheError::StorageChanged {
                    address,
                    slot: *slot,
                });
            }
        }

        self.accounts
            .entry(address)
            .or_insert_with(|| proof.account.clone());
        for (slot, value) in proof.storage.into_iter().take(real_keys.len()) {
            self.storage.entry((address, slot)).or_insert(value);
        }
        Ok(())
    }

    /// Return a cached account converted to revm's representation.
    pub fn account_info(
        &self,
        address: Address,
    ) -> Result<Option<Option<AccountInfo>>, CacheError> {
        if let Some(local) = self.local_accounts.get(&address) {
            return Ok(Some(Some(local.clone())));
        }
        let Some(account) = self.accounts.get(&address) else {
            return Ok(None);
        };
        let Some(account) = account else {
            return Ok(Some(None));
        };

        let code = if account.code_hash == KECCAK_EMPTY {
            Some(Bytecode::default())
        } else if let Some((actual_hash, bytecode)) = self.address_bytecodes.get(&address) {
            if *actual_hash != account.code_hash {
                return Err(CacheError::BytecodeHash {
                    address,
                    got: *actual_hash,
                    expected: account.code_hash,
                });
            }
            Some(bytecode.clone())
        } else {
            self.bytecodes.get(&account.code_hash).cloned()
        };

        Ok(Some(Some(AccountInfo {
            balance: account.balance,
            nonce: account.nonce,
            code_hash: account.code_hash,
            account_id: None,
            code,
        })))
    }

    /// Return a cached storage value.
    pub fn storage(&self, address: Address, slot: U256) -> Option<U256> {
        self.storage.get(&(address, slot)).copied()
    }

    /// Return preloaded bytecode.
    pub fn bytecode(&self, hash: B256) -> Option<Bytecode> {
        self.bytecodes.get(&hash).cloned()
    }

    /// Return a preloaded block hash.
    pub fn block_hash(&self, number: u64) -> Option<B256> {
        self.block_hashes.get(&number).copied()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, bytes};

    #[test]
    fn address_bytecode_is_checked_against_proof_hash() {
        let address = address!("1000000000000000000000000000000000000000");
        let mut cache = ProofCache::default();
        cache.preload_bytecode_at(address, bytes!("6000"));
        cache
            .apply_verified(
                address,
                &[],
                VerifiedProof {
                    account: Some(VerifiedAccount {
                        nonce: 1,
                        balance: U256::ZERO,
                        storage_root: B256::ZERO,
                        code_hash: B256::repeat_byte(1),
                    }),
                    storage: vec![],
                },
            )
            .unwrap();
        assert!(matches!(
            cache.account_info(address),
            Err(CacheError::BytecodeHash { .. })
        ));
    }

    #[test]
    fn authenticated_storage_must_match_real_keys() {
        let mut cache = ProofCache::default();
        let error = cache
            .apply_verified(
                Address::ZERO,
                &[U256::from(1)],
                VerifiedProof {
                    account: None,
                    storage: vec![],
                },
            )
            .unwrap_err();
        assert_eq!(error, CacheError::StorageShape);
    }
}
