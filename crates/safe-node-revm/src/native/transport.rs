use crate::rpc::{JsonRpcRequest, JsonRpcResponse};
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use reqwest::Url;
use rustls::{
    ClientConfig, DigitallySignedStruct, Error as RustlsError, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{WebPkiSupportedAlgorithms, ring},
    pki_types::{CertificateDer, ServerName, UnixTime},
};
use sha2::{Digest, Sha256};
use std::{error::Error as StdError, sync::Arc, time::Duration};
use thiserror::Error;
use x509_parser::prelude::FromDer;

/// Failure before a valid JSON-RPC envelope is available.
#[derive(Debug, Error)]
pub enum TransportError {
    /// The attested key no longer matches. No request should be retried until
    /// first-contact attestation is run again.
    #[error("attested TLS pin mismatch; stop and re-attest Safe Node")]
    PinMismatch,
    /// Invalid pin or TLS configuration.
    #[error("TLS configuration error: {0}")]
    TlsConfig(String),
    /// HTTP/TLS/request timeout failure.
    #[error("HTTP transport error: {0}")]
    Http(String),
    /// Non-success HTTP status.
    #[error("Safe Node returned HTTP {status}: {body}")]
    HttpStatus {
        /// Status code.
        status: u16,
        /// Truncated response body.
        body: String,
    },
    /// Response exceeded the configured hard limit.
    #[error("Safe Node response exceeded 32 MiB")]
    ResponseTooLarge,
    /// Invalid JSON-RPC response.
    #[error("invalid JSON-RPC response: {0}")]
    Json(String),
}

/// Pluggable scheduled JSON-RPC transport.
#[async_trait]
pub trait RpcTransport: Send + Sync + 'static {
    /// Send exactly one already-scheduled request.
    async fn send(&self, request: JsonRpcRequest) -> Result<JsonRpcResponse, TransportError>;
}

/// Reqwest transport that trusts exactly an attestation-discovered SPKI hash.
#[derive(Clone, Debug)]
pub struct PinnedHttpTransport {
    client: reqwest::Client,
    rpc_url: Url,
}

impl PinnedHttpTransport {
    /// Build a transport from a curl-style `sha256//BASE64` public-key pin.
    pub fn new(
        rpc_url: impl AsRef<str>,
        attested_domain: impl Into<String>,
        pin: &str,
        timeout: Duration,
    ) -> Result<Self, TransportError> {
        let rpc_url = Url::parse(rpc_url.as_ref())
            .map_err(|error| TransportError::TlsConfig(error.to_string()))?;
        if rpc_url.scheme() != "https" {
            return Err(TransportError::TlsConfig(
                "pinned transport requires https".to_owned(),
            ));
        }
        let expected_domain = attested_domain.into().to_ascii_lowercase();
        let url_domain = rpc_url.host_str().ok_or_else(|| {
            TransportError::TlsConfig("RPC URL must contain a DNS host".to_owned())
        })?;
        if !url_domain.eq_ignore_ascii_case(&expected_domain) {
            return Err(TransportError::TlsConfig(format!(
                "RPC URL host {url_domain} does not match attested domain {expected_domain}"
            )));
        }
        if !rpc_url.username().is_empty() || rpc_url.password().is_some() {
            return Err(TransportError::TlsConfig(
                "RPC URL must not contain userinfo".to_owned(),
            ));
        }

        let expected_pin = parse_pin(pin)?;
        let provider = ring::default_provider();
        let algorithms = provider.signature_verification_algorithms;
        let verifier = Arc::new(SpkiPinVerifier {
            expected_domain,
            expected_pin,
            algorithms,
        });
        let mut tls = ClientConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .map_err(|error| TransportError::TlsConfig(error.to_string()))?
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];

        let client = reqwest::Client::builder()
            .use_preconfigured_tls(tls)
            .redirect(reqwest::redirect::Policy::none())
            .timeout(timeout)
            .http2_adaptive_window(true)
            .build()
            .map_err(|error| TransportError::TlsConfig(error.to_string()))?;
        Ok(Self { client, rpc_url })
    }
}

#[async_trait]
impl RpcTransport for PinnedHttpTransport {
    async fn send(&self, request: JsonRpcRequest) -> Result<JsonRpcResponse, TransportError> {
        let mut response = self
            .client
            .post(self.rpc_url.clone())
            .json(&request)
            .send()
            .await
            .map_err(classify_reqwest_error)?;
        let status = response.status();
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(classify_reqwest_error)? {
            if body.len().saturating_add(chunk.len()) > 32 * 1024 * 1024 {
                return Err(TransportError::ResponseTooLarge);
            }
            body.extend_from_slice(&chunk);
        }
        if !status.is_success() {
            return Err(TransportError::HttpStatus {
                status: status.as_u16(),
                body: String::from_utf8_lossy(&body).chars().take(512).collect(),
            });
        }
        let text =
            std::str::from_utf8(&body).map_err(|error| TransportError::Json(error.to_string()))?;
        JsonRpcResponse::parse(text).map_err(|error| TransportError::Json(error.to_string()))
    }
}

fn parse_pin(pin: &str) -> Result<[u8; 32], TransportError> {
    let encoded = pin
        .strip_prefix("sha256//")
        .ok_or_else(|| TransportError::TlsConfig("pin must use sha256//BASE64 form".to_owned()))?;
    let bytes = STANDARD
        .decode(encoded)
        .map_err(|error| TransportError::TlsConfig(error.to_string()))?;
    bytes
        .try_into()
        .map_err(|_| TransportError::TlsConfig("SPKI SHA-256 pin must contain 32 bytes".to_owned()))
}

fn classify_reqwest_error(error: reqwest::Error) -> TransportError {
    let mut messages = vec![error.to_string()];
    let mut source = error.source();
    while let Some(next) = source {
        messages.push(next.to_string());
        source = next.source();
    }
    if messages
        .iter()
        .any(|message| message.contains("attested TLS pin mismatch"))
    {
        TransportError::PinMismatch
    } else {
        TransportError::Http(messages.join(": "))
    }
}

#[derive(Debug)]
struct SpkiPinVerifier {
    expected_domain: String,
    expected_pin: [u8; 32],
    algorithms: WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for SpkiPinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let actual_domain = match server_name {
            ServerName::DnsName(name) => name.as_ref(),
            _ => {
                return Err(RustlsError::General(
                    "attested TLS requires a DNS server name".to_owned(),
                ));
            }
        };
        if !actual_domain.eq_ignore_ascii_case(&self.expected_domain) {
            return Err(RustlsError::General(format!(
                "attested TLS domain mismatch: got {actual_domain}, expected {}",
                self.expected_domain
            )));
        }

        let (_, certificate) = x509_parser::certificate::X509Certificate::from_der(
            end_entity.as_ref(),
        )
        .map_err(|error| RustlsError::General(format!("invalid leaf certificate: {error}")))?;
        let spki = certificate.tbs_certificate.subject_pki.raw;
        let actual: [u8; 32] = Sha256::digest(spki).into();
        if actual != self.expected_pin {
            return Err(RustlsError::General(
                "attested TLS pin mismatch; re-attestation required".to_owned(),
            ));
        }
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.algorithms.supported_schemes()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pin_parser_is_strict() {
        assert!(parse_pin("sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").is_ok());
        assert!(parse_pin("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=").is_err());
        assert!(parse_pin("sha256//AA==").is_err());
    }

    #[test]
    fn rpc_url_must_match_the_attested_domain() {
        let error = PinnedHttpTransport::new(
            "https://example.com/json_rpc",
            "rpc-gcp.safe-node.com",
            "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert!(matches!(error, TransportError::TlsConfig(_)));
    }
}
