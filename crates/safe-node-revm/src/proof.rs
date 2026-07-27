use crate::rpc::GetProofResponse;
use alloy_primitives::{Address, B256, U256, keccak256};
use alloy_trie::{EMPTY_ROOT_HASH, KECCAK_EMPTY, Nibbles, TrieAccount, proof::verify_proof};
use thiserror::Error;

/// Account fields authenticated by the state trie.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedAccount {
    /// Account nonce.
    pub nonce: u64,
    /// Account balance.
    pub balance: U256,
    /// Root of the account's storage trie.
    pub storage_root: B256,
    /// Hash of account bytecode.
    pub code_hash: B256,
}

/// Authenticated account and requested storage values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedProof {
    /// `None` for a proven absent account.
    pub account: Option<VerifiedAccount>,
    /// Values in the same order as the requested storage keys, including
    /// repeated padding keys.
    pub storage: Vec<(U256, U256)>,
}

/// MPT or response-shape validation failure.
#[derive(Debug, Error)]
pub enum ProofError {
    /// Account proof failed verification.
    #[error("account MPT proof failed: {0}")]
    Account(String),
    /// Storage proof failed verification.
    #[error("storage MPT proof for slot {slot:#x} failed: {message}")]
    Storage {
        /// Unhashed storage slot.
        slot: U256,
        /// Underlying verification error.
        message: String,
    },
    /// Safe Node returned a different number of storage proofs.
    #[error("storage proof count mismatch: got {got}, expected {expected}")]
    StorageCount {
        /// Number returned.
        got: usize,
        /// Number requested.
        expected: usize,
    },
    /// Safe Node returned a proof for a different slot or in a different order.
    #[error("storage proof key mismatch at index {index}: got {got:#x}, expected {expected:#x}")]
    StorageKey {
        /// Entry index.
        index: usize,
        /// Returned slot.
        got: U256,
        /// Requested slot.
        expected: U256,
    },
}

/// Authenticate an EIP-1186-style response against a trusted state root.
///
/// The account path is `keccak256(address)`. Each storage path is
/// `keccak256(slot_be_32)`. Non-zero storage values are matched against their
/// canonical RLP scalar; zero values are verified as exclusions.
pub fn verify_response(
    state_root: B256,
    address: Address,
    requested_slots: &[U256],
    response: &GetProofResponse,
) -> Result<VerifiedProof, ProofError> {
    let canonical_empty = response.nonce == 0
        && response.balance.is_zero()
        && response.storage_hash == EMPTY_ROOT_HASH
        && response.code_hash == KECCAK_EMPTY;

    let account = TrieAccount {
        nonce: response.nonce,
        balance: response.balance,
        storage_root: response.storage_hash,
        code_hash: response.code_hash,
    };
    let account_path = Nibbles::unpack(keccak256(address));
    // At current Ethereum blocks canonical-empty fields mean an absent account.
    // For completeness at old/pre-EIP-161 roots, accept an inclusion proof for
    // an explicitly stored empty account and report it as present.
    let account_absent = if canonical_empty {
        match verify_proof(state_root, account_path, None, &response.account_proof) {
            Ok(()) => true,
            Err(exclusion_error) => {
                verify_proof(
                    state_root,
                    account_path,
                    Some(alloy_rlp::encode(account)),
                    &response.account_proof,
                )
                .map_err(|_| ProofError::Account(exclusion_error.to_string()))?;
                false
            }
        }
    } else {
        verify_proof(
            state_root,
            account_path,
            Some(alloy_rlp::encode(account)),
            &response.account_proof,
        )
        .map_err(|error| ProofError::Account(error.to_string()))?;
        false
    };

    if response.storage_proof.len() != requested_slots.len() {
        return Err(ProofError::StorageCount {
            got: response.storage_proof.len(),
            expected: requested_slots.len(),
        });
    }

    let mut storage = Vec::with_capacity(requested_slots.len());
    for (index, (expected_key, returned)) in requested_slots
        .iter()
        .copied()
        .zip(&response.storage_proof)
        .enumerate()
    {
        if returned.key != expected_key {
            return Err(ProofError::StorageKey {
                index,
                got: returned.key,
                expected: expected_key,
            });
        }
        let hashed_key = keccak256(expected_key.to_be_bytes::<32>());
        let expected_value = (!returned.value.is_zero()).then(|| {
            alloy_rlp::encode_fixed_size(&returned.value)
                .as_ref()
                .to_vec()
        });
        verify_proof(
            response.storage_hash,
            Nibbles::unpack(hashed_key),
            expected_value,
            &returned.proof,
        )
        .map_err(|error| ProofError::Storage {
            slot: expected_key,
            message: error.to_string(),
        })?;
        storage.push((expected_key, returned.value));
    }

    Ok(VerifiedProof {
        account: (!account_absent).then_some(VerifiedAccount {
            nonce: response.nonce,
            balance: response.balance,
            storage_root: response.storage_hash,
            code_hash: response.code_hash,
        }),
        storage,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::Deserialize;

    #[derive(Deserialize)]
    #[serde(rename_all = "camelCase")]
    struct Fixture {
        state_root: B256,
        address: Address,
        slot: U256,
        proof: GetProofResponse,
    }

    fn fixture() -> Fixture {
        serde_json::from_str(crate::SEPOLIA_WETH9_FIXTURE).unwrap()
    }

    #[test]
    fn verifies_real_sepolia_account_and_storage_proofs() {
        let fixture = fixture();
        let verified = verify_response(
            fixture.state_root,
            fixture.address,
            &[fixture.slot],
            &fixture.proof,
        )
        .unwrap();
        assert!(verified.account.is_some());
        assert_eq!(
            verified.storage[0],
            (fixture.slot, fixture.proof.storage_proof[0].value)
        );
    }

    #[test]
    fn rejects_tampered_account_fields() {
        let mut fixture = fixture();
        fixture.proof.balance += U256::from(1);
        assert!(matches!(
            verify_response(
                fixture.state_root,
                fixture.address,
                &[fixture.slot],
                &fixture.proof
            ),
            Err(ProofError::Account(_))
        ));
    }

    #[test]
    fn rejects_tampered_storage_value() {
        let mut fixture = fixture();
        fixture.proof.storage_proof[0].value += U256::from(1);
        assert!(matches!(
            verify_response(
                fixture.state_root,
                fixture.address,
                &[fixture.slot],
                &fixture.proof
            ),
            Err(ProofError::Storage { .. })
        ));
    }
}
