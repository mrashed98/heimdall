//! `heimdall scan-images`: the CronJob that gives images an SBOM.
//!
//! It asks Bifröst which image digests have none, runs syft on each and
//! uploads the CycloneDX result. Keeping this in a separate job keeps the
//! memory-hungry scanning out of the 1 GB main pod.

use std::path::Path;
use std::process::Stdio;
use std::time::Duration;

use anyhow::{bail, Context};
use serde::Deserialize;
use tokio::process::Command;

use crate::client::Client;

/// One syft run is killed after this long so a stuck pull cannot hang the Job.
const SYFT_TIMEOUT: Duration = Duration::from_secs(600);

/// How much of syft's stderr goes into the log line for a failure.
const STDERR_TAIL_BYTES: usize = 1000;

#[derive(Debug, Deserialize)]
struct Pending {
    digest: String,
    /// `{repository_url}@{digest}`, so the digest is already in it.
    image_ref: String,
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct ScanReport {
    pub scanned: usize,
    pub failed: usize,
}

/// Scan up to `max` pending images. A failing image is logged and counted;
/// the rest are still tried. Only listing the pending images can fail the
/// whole run.
pub async fn run(client: &Client, syft: &Path, max: usize) -> anyhow::Result<ScanReport> {
    let pending: Vec<Pending> = client.get_json("/api/v1/images/pending").await?;
    let mut report = ScanReport::default();
    for item in pending.into_iter().take(max) {
        match scan_one(client, syft, &item).await {
            Ok(()) => {
                println!("scanned {}", item.image_ref);
                report.scanned += 1;
            }
            Err(e) => {
                eprintln!("failed {}: {e:#}", item.image_ref);
                report.failed += 1;
                // Reported so the next run tries the other images first.
                if let Err(r) = report_failure(client, &item, &format!("{e:#}")).await {
                    eprintln!("could not report the failure of {}: {r:#}", item.image_ref);
                }
            }
        }
    }
    Ok(report)
}

async fn scan_one(client: &Client, syft: &Path, item: &Pending) -> anyhow::Result<()> {
    let sbom = run_syft(syft, &item.image_ref).await?;
    let path = format!(
        "/api/v1/ingest/image/{}?image_ref={}",
        Client::encode_segment(&item.digest),
        Client::encode_segment(&item.image_ref)
    );
    let _: serde_json::Value = client
        .post_bytes(&path, sbom)
        .await
        .context("uploading the SBOM")?;
    Ok(())
}

async fn report_failure(client: &Client, item: &Pending, error: &str) -> anyhow::Result<()> {
    let path = format!(
        "/api/v1/images/{}/failed",
        Client::encode_segment(&item.digest)
    );
    let body = serde_json::json!({ "error": error });
    let _: serde_json::Value = client.post_json(&path, &body).await?;
    Ok(())
}

/// Run syft and return its stdout (the CycloneDX JSON). DOCKER_CONFIG and
/// the rest of the environment are inherited for registry credentials.
async fn run_syft(syft: &Path, image_ref: &str) -> anyhow::Result<Vec<u8>> {
    let child = Command::new(syft)
        .arg(format!("registry:{image_ref}"))
        .args(["-o", "cyclonedx-json"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        // Dropping the child on timeout must not leave syft running.
        .kill_on_drop(true)
        .spawn()
        .with_context(|| format!("starting {}", syft.display()))?;

    let out = match tokio::time::timeout(SYFT_TIMEOUT, child.wait_with_output()).await {
        Ok(result) => result.context("waiting for syft")?,
        // The timeout drops the future and with it the child, which kills it.
        Err(_) => bail!("syft timed out after {}s", SYFT_TIMEOUT.as_secs()),
    };
    if !out.status.success() {
        bail!("syft exited with {}: {}", out.status, tail(&out.stderr));
    }
    Ok(out.stdout)
}

/// The last bytes of stderr as text, so logs stay short.
fn tail(stderr: &[u8]) -> String {
    let start = stderr.len().saturating_sub(STDERR_TAIL_BYTES);
    String::from_utf8_lossy(&stderr[start..]).trim().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use wiremock::matchers::{method, path, path_regex};
    use wiremock::{Mock, MockServer, ResponseTemplate};

    const SBOM: &str = include_str!("../tests/fixtures/sbom/go-service.cdx.json");

    /// A stand-in for syft: prints the fixture SBOM, or fails when the image
    /// reference contains "bad". `$1` is `registry:<image_ref>`.
    fn fake_syft(dir: &Path) -> std::path::PathBuf {
        let fixture = dir.join("sbom.json");
        std::fs::write(&fixture, SBOM).unwrap();
        let script = dir.join("syft");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\ncase \"$1\" in\n  *bad*) echo 'boom: cannot pull' >&2; exit 1;;\nesac\n\
                 [ \"$2\" = \"-o\" ] && [ \"$3\" = \"cyclonedx-json\" ] || exit 3\ncat {}\n",
                fixture.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        script
    }

    fn pending_json() -> serde_json::Value {
        let good = format!("sha256:{}", "a".repeat(64));
        let bad = format!("sha256:bad{}", "b".repeat(61));
        serde_json::json!([
            { "digest": good, "image_ref": format!("ghcr.io/o/app@{good}") },
            { "digest": bad, "image_ref": format!("ghcr.io/o/bad@{bad}") },
        ])
    }

    #[tokio::test]
    async fn scans_pending_and_continues_on_failure() {
        let server = MockServer::start().await;
        Mock::given(method("GET"))
            .and(path("/api/v1/images/pending"))
            .respond_with(ResponseTemplate::new(200).set_body_json(pending_json()))
            .mount(&server)
            .await;
        Mock::given(method("POST"))
            .and(path_regex("^/api/v1/(ingest/image/|images/.*/failed$)"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({})))
            .mount(&server)
            .await;

        let tmp = tempfile::tempdir().unwrap();
        let syft = fake_syft(tmp.path());
        let client = Client::new(&server.uri(), "k".into());
        let report = run(&client, &syft, 20).await.unwrap();
        assert_eq!(
            report,
            ScanReport {
                scanned: 1,
                failed: 1
            }
        );

        let posts: Vec<_> = server
            .received_requests()
            .await
            .unwrap()
            .into_iter()
            .filter(|r| r.method.as_str() == "POST")
            .collect();
        let (uploads, failures): (Vec<_>, Vec<_>) = posts
            .into_iter()
            .partition(|r| r.url.path().starts_with("/api/v1/ingest/image/"));
        assert_eq!(uploads.len(), 1);
        assert_eq!(uploads[0].body, SBOM.as_bytes());
        let q = uploads[0].url.query().unwrap_or_default().to_string();
        assert!(q.starts_with("image_ref=ghcr.io"), "query was {q}");
        // The failure is reported, so the bad image goes to the back of the queue.
        assert_eq!(failures.len(), 1);
        let bad = format!("sha256:bad{}", "b".repeat(61));
        let encoded = Client::encode_segment(&bad);
        assert_eq!(
            failures[0].url.path(),
            format!("/api/v1/images/{encoded}/failed")
        );
        let body: serde_json::Value = serde_json::from_slice(&failures[0].body).unwrap();
        assert!(
            body["error"].as_str().unwrap().contains("cannot pull"),
            "{body}"
        );
    }
}
