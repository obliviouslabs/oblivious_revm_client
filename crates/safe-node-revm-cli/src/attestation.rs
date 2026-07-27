use anyhow::{Context, Result, bail, ensure};
use rand::Rng;
use serde::Deserialize;
use sha2::{Digest, Sha384};
use std::{collections::HashMap, path::PathBuf, process::Command, time::Duration};

pub const DEFAULT_BASE_URL: &str = "https://rpc-gcp.safe-node.com";
pub const DEFAULT_TLS_DOMAIN: &str = "rpc-gcp.safe-node.com";
pub const EXPECTED_IMAGE_DIGEST: &str =
    "sha256:a3fd25a16be611d193e63fb9c422eda212d61cb6adeb4801acd596e2842c6f2d";
pub const EXPECTED_ROOT_CAPACITY: &str = "33554432";
pub const EXPECTED_NODE_CAPACITY: &str = "4194304";

#[derive(Clone, Debug)]
pub struct AttestationResult {
    pub pin: String,
    pub workload_digest: String,
    pub transcript: String,
}

#[derive(Deserialize)]
struct BootstrapResponse {
    workload_manifest: String,
}

#[derive(Deserialize)]
struct WorkloadManifest {
    schema: String,
    entrypoint: String,
    rtmr: String,
    image_digest: String,
    env: HashMap<String, String>,
}

/// Policy-check one manifest, then require the official quote verifier's fresh
/// request to contain the exact same SHA-384 manifest digest.
pub async fn verify_first_contact(base_url: &str, tls_domain: &str) -> Result<AttestationResult> {
    let manifest_text = fetch_untrusted_manifest(base_url, tls_domain).await?;
    check_manifest_policy(&manifest_text, tls_domain)?;
    let workload_digest = format!("0x{}", hex_digest(Sha384::digest(manifest_text.as_bytes())));

    let script = verifier_script();
    ensure!(
        script.is_file(),
        "tdx_easy_https verifier not found at {}; initialize git submodules",
        script.display()
    );
    let output = Command::new("node")
        .arg(&script)
        .arg(base_url)
        .args(["--gcp-attestd", "--tls-domain", tls_domain])
        .args(["--expected-gcp-image-digest", EXPECTED_IMAGE_DIGEST])
        .args([
            "--expected-gcp-env",
            &format!("ROOT_MAP_CAPACITY={EXPECTED_ROOT_CAPACITY}"),
        ])
        .args([
            "--expected-gcp-env",
            &format!("NODE_MAP_CAPACITY={EXPECTED_NODE_CAPACITY}"),
        ])
        .args(["--expected-gcp-workload-digest", &workload_digest])
        .output()
        .with_context(|| format!("failed to start Node verifier at {}", script.display()))?;
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    if !output.status.success() {
        bail!("TDX verification failed: {}", stderr.trim());
    }
    ensure!(
        stdout
            .lines()
            .any(|line| line == "gcp_attestd_quote_verified=true"),
        "TDX verifier did not confirm the quote"
    );
    let pin = output_value(&stdout, "attested_tls_pin=")
        .context("TDX verifier did not return attested_tls_pin")?;
    let verified_digest = output_value(&stdout, "gcp_workload_digest_sha384=")
        .context("TDX verifier did not return the workload digest")?;
    ensure!(
        verified_digest.eq_ignore_ascii_case(&workload_digest),
        "quote-verified workload digest changed between policy check and verification"
    );

    Ok(AttestationResult {
        pin,
        workload_digest,
        transcript: stdout,
    })
}

async fn fetch_untrusted_manifest(base_url: &str, tls_domain: &str) -> Result<String> {
    let mut challenge = [0_u8; 32];
    rand::rng().fill(&mut challenge);
    let base_url = reqwest::Url::parse(base_url).context("invalid Safe Node base URL")?;
    ensure!(
        base_url.scheme() == "https",
        "Safe Node base URL must use HTTPS"
    );
    ensure!(
        base_url
            .host_str()
            .is_some_and(|host| host.eq_ignore_ascii_case(tls_domain)),
        "Safe Node base URL host must match the attested TLS domain"
    );
    let url = base_url.join("/attestd/")?;

    // This first response is deliberately untrusted. Its exact manifest digest
    // is supplied to the independent quote verifier below before any pin is used.
    let client = reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(30))
        .build()?;
    let mut response = client
        .post(url)
        .json(&serde_json::json!({
            "domain": tls_domain,
            "challenge": hex_digest(challenge),
        }))
        .send()
        .await?
        .error_for_status()?;
    let mut body = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            body.len().saturating_add(chunk.len()) <= 1024 * 1024,
            "attestation bootstrap response exceeded 1 MiB"
        );
        body.extend_from_slice(&chunk);
    }
    Ok(serde_json::from_slice::<BootstrapResponse>(&body)?.workload_manifest)
}

fn check_manifest_policy(text: &str, tls_domain: &str) -> Result<()> {
    let manifest: WorkloadManifest =
        serde_json::from_str(text).context("workload_manifest is not valid JSON")?;
    ensure!(
        manifest.schema == "safe-node.gcp.tdx-container.v1",
        "unexpected manifest schema"
    );
    ensure!(
        manifest.entrypoint == "/usr/local/bin/safe-node-gcp-entrypoint",
        "unexpected workload entrypoint"
    );
    ensure!(
        manifest.rtmr == "rtmr3:sha384",
        "unexpected workload RTMR policy"
    );
    ensure!(
        manifest.image_digest == EXPECTED_IMAGE_DIGEST,
        "workload image digest mismatch"
    );
    require_env(&manifest.env, "SERVER_DOMAIN", tls_domain)?;
    require_env(&manifest.env, "ETH_NETWORK", "sepolia")?;
    require_env(&manifest.env, "GCP_ATTESTATION_MODE", "tdx")?;
    require_env(
        &manifest.env,
        "CONFIDENTIAL_SPACE_AUDIENCE",
        &format!("safe-node:{tls_domain}"),
    )?;
    require_env(
        &manifest.env,
        "WORKLOAD_IMAGE_DIGEST",
        EXPECTED_IMAGE_DIGEST,
    )?;
    require_env(&manifest.env, "ROOT_MAP_CAPACITY", EXPECTED_ROOT_CAPACITY)?;
    require_env(&manifest.env, "NODE_MAP_CAPACITY", EXPECTED_NODE_CAPACITY)?;
    Ok(())
}

fn require_env(env: &HashMap<String, String>, key: &str, expected: &str) -> Result<()> {
    ensure!(
        env.get(key).map(String::as_str) == Some(expected),
        "workload environment mismatch for {key}"
    );
    Ok(())
}

fn verifier_script() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../external/tdx_easy_https/client/node/verify_client_tdx.mjs")
}

fn output_value(output: &str, prefix: &str) -> Option<String> {
    output
        .lines()
        .filter_map(|line| line.strip_prefix(prefix))
        .next_back()
        .map(str::to_owned)
}

fn hex_digest(bytes: impl AsRef<[u8]>) -> String {
    bytes
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_changed_manifest_policy() {
        let text = serde_json::json!({
            "schema": "safe-node.gcp.tdx-container.v1",
            "entrypoint": "/usr/local/bin/safe-node-gcp-entrypoint",
            "rtmr": "rtmr3:sha384",
            "image_digest": "sha256:wrong",
            "env": {
                "SERVER_DOMAIN": DEFAULT_TLS_DOMAIN,
                "ETH_NETWORK": "sepolia",
                "GCP_ATTESTATION_MODE": "tdx",
                "CONFIDENTIAL_SPACE_AUDIENCE": format!("safe-node:{}", DEFAULT_TLS_DOMAIN),
                "WORKLOAD_IMAGE_DIGEST": EXPECTED_IMAGE_DIGEST,
                "ROOT_MAP_CAPACITY": EXPECTED_ROOT_CAPACITY,
                "NODE_MAP_CAPACITY": EXPECTED_NODE_CAPACITY
            }
        });
        assert!(check_manifest_policy(&text.to_string(), DEFAULT_TLS_DOMAIN).is_err());
    }
}
