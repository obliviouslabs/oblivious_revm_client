use alloy_primitives::{Address, B256, Bytes, U256};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::Value;

/// A block selector accepted by Safe Node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockSelector {
    /// An immutable block number, encoded as a JSON-RPC quantity.
    Number(u64),
    /// An EIP-1898 block-hash selector.
    Hash {
        /// Block hash.
        block_hash: B256,
        /// Safe Node currently requires this to be false.
        require_canonical: bool,
    },
    /// A named selector. `latest` is useful for smoke tests but should not be
    /// used for a multi-request EVM execution because its state can move.
    Tag(String),
}

impl BlockSelector {
    /// Construct the `latest` selector.
    pub fn latest() -> Self {
        Self::Tag("latest".to_owned())
    }
}

impl Serialize for BlockSelector {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Number(number) => serializer.serialize_str(&format!("0x{number:x}")),
            Self::Tag(tag) => serializer.serialize_str(tag),
            Self::Hash {
                block_hash,
                require_canonical,
            } => {
                #[derive(Serialize)]
                #[serde(rename_all = "camelCase")]
                struct HashSelector<'a> {
                    block_hash: &'a B256,
                    require_canonical: bool,
                }
                HashSelector {
                    block_hash,
                    require_canonical: *require_canonical,
                }
                .serialize(serializer)
            }
        }
    }
}

/// One storage proof returned by `eth_getProof`.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct StorageProof {
    /// Storage slot before hashing.
    pub key: U256,
    /// Value committed at this slot.
    pub value: U256,
    /// MPT nodes from storage root to the value or exclusion point.
    pub proof: Vec<Bytes>,
}

/// Safe Node's EIP-1186-style result.
///
/// Safe Node intentionally does not currently include the standard `address`
/// field, so the requested address is supplied separately to proof verification.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct GetProofResponse {
    /// Account nonce.
    #[serde(deserialize_with = "deserialize_quantity_u64")]
    pub nonce: u64,
    /// Account balance.
    pub balance: U256,
    /// Account storage root.
    pub storage_hash: B256,
    /// Hash of account bytecode.
    pub code_hash: B256,
    /// MPT nodes from state root to the account or exclusion point.
    pub account_proof: Vec<Bytes>,
    /// Requested storage proofs, in request order.
    pub storage_proof: Vec<StorageProof>,
}

fn deserialize_quantity_u64<'de, D>(deserializer: D) -> Result<u64, D::Error>
where
    D: Deserializer<'de>,
{
    let value = U256::deserialize(deserializer)?;
    value
        .try_into()
        .map_err(|_| serde::de::Error::custom("nonce does not fit in u64"))
}

/// JSON-RPC error object.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct JsonRpcError {
    /// JSON-RPC error code.
    pub code: i64,
    /// Human-readable message.
    pub message: String,
    /// Optional implementation-specific data.
    #[serde(default)]
    pub data: Option<Value>,
}

/// A JSON-RPC `eth_getProof` request with fixed-width account and slot fields.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct JsonRpcRequest {
    jsonrpc: &'static str,
    /// Fixed-width string identifier.
    pub id: String,
    method: &'static str,
    params: GetProofParams,
}

#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
struct GetProofParams(String, Vec<String>, BlockSelector);

impl JsonRpcRequest {
    /// Build an `eth_getProof` request.
    pub fn get_proof(
        id: String,
        address: Address,
        storage_keys: &[U256],
        block: BlockSelector,
    ) -> Self {
        Self {
            jsonrpc: "2.0",
            id,
            method: "eth_getProof",
            params: GetProofParams(
                fixed_address(address),
                storage_keys.iter().copied().map(fixed_slot).collect(),
                block,
            ),
        }
    }

    /// Requested account.
    pub fn address(&self) -> Address {
        // Construction guarantees this parse succeeds.
        self.params.0.parse().expect("internally formatted address")
    }

    /// Requested storage keys.
    pub fn storage_keys(&self) -> Vec<U256> {
        self.params
            .1
            .iter()
            .map(|key| key.parse().expect("internally formatted storage key"))
            .collect()
    }
}

/// A JSON-RPC response envelope.
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
pub struct JsonRpcResponse {
    /// Protocol version.
    pub jsonrpc: String,
    /// Echoed identifier.
    pub id: Value,
    /// Successful result.
    #[serde(default)]
    pub result: Option<GetProofResponse>,
    /// Error result.
    #[serde(default)]
    pub error: Option<JsonRpcError>,
}

impl JsonRpcResponse {
    /// Parse a response and require exactly one of `result` or `error`.
    pub fn parse(text: &str) -> Result<Self, serde_json::Error> {
        let response: Self = serde_json::from_str(text)?;
        if response.jsonrpc != "2.0" {
            return Err(serde::de::Error::custom(
                "response jsonrpc field is not 2.0",
            ));
        }
        if response.result.is_some() == response.error.is_some() {
            return Err(serde::de::Error::custom(
                "response must contain exactly one of result or error",
            ));
        }
        Ok(response)
    }
}

/// Lower-case, fixed-width 20-byte address.
pub fn fixed_address(address: Address) -> String {
    format!("0x{}", hex::encode(address.as_slice()))
}

/// Lower-case, fixed-width 32-byte storage slot.
pub fn fixed_slot(slot: U256) -> String {
    format!("0x{}", hex::encode(slot.to_be_bytes::<32>()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::{address, uint};

    #[test]
    fn request_fields_are_fixed_width() {
        let request = JsonRpcRequest::get_proof(
            "0000000000000001".to_owned(),
            address!("0000000000000000000000000000000000000001"),
            &[uint!(1_U256)],
            BlockSelector::Number(1),
        );
        let json = serde_json::to_string(&request).unwrap();
        assert!(json.contains("0x0000000000000000000000000000000000000001"));
        assert!(
            json.contains("0x0000000000000000000000000000000000000000000000000000000000000001")
        );
        assert!(json.contains("\"0x1\""));
    }

    #[test]
    fn response_envelope_requires_jsonrpc_2_and_one_outcome() {
        assert!(
            JsonRpcResponse::parse(
                r#"{"jsonrpc":"1.0","id":"1","error":{"code":-1,"message":"x"}}"#
            )
            .is_err()
        );
        assert!(JsonRpcResponse::parse(r#"{"jsonrpc":"2.0","id":"1"}"#).is_err());
        assert!(
            JsonRpcResponse::parse(
                r#"{"jsonrpc":"2.0","id":"1","result":null,"error":{"code":-1,"message":"x"}}"#
            )
            .is_ok()
        );
    }
}
