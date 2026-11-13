use std::path::PathBuf;
use std::process::ExitCode;

use chrono::NaiveDate;
use clap::{Args, Parser, Subcommand};
use heimdall::auth::{CreateKeyRequest, CreateKeyResponse, KeyInfo, Scope};
use heimdall::client::Client;
use heimdall::config::HeimdallConfig;
use heimdall::gate::{self, GateResponse};
use heimdall::ingest::manifests::direct_name_keys;
use heimdall::model::{OathKind, Severity};
use heimdall::oath::{ExtendBody, NewOathBody, Oath};

#[derive(Parser)]
#[command(
    name = "heimdall",
    version,
    about = "Vulnerability and release tracker"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Run the server (or just validate the config with --check-config)
    Serve {
        /// Parse the config file, print "config ok" and exit
        #[arg(long)]
        check_config: bool,
        /// Path to heimdall.yaml
        config: Option<PathBuf>,
    },
    /// Hofund: CI gate. Exit 0 pass, 1 fail, 2 unverified or server unreachable
    Gate(GateArgs),
    /// Oaths (suppressions)
    Oath {
        #[command(subcommand)]
        action: OathAction,
    },
    /// API keys
    Keys {
        #[command(subcommand)]
        action: KeysAction,
    },
    /// Sight: inventory scanning
    Sight,
    /// Generate SBOMs for images that have none
    ScanImages,
    /// Realms
    Realms,
}

#[derive(Args)]
struct GateArgs {
    /// Service name
    #[arg(long)]
    service: String,
    /// Realm
    #[arg(long)]
    realm: String,
    /// CycloneDX JSON SBOM
    #[arg(long)]
    sbom: PathBuf,
    /// Lowest severity that fails the build
    #[arg(long, value_parser = gate::parse_severity)]
    fail_on: Severity,
    /// Where go.mod / package.json files are read for direct dependencies
    #[arg(long, default_value = ".")]
    repo_root: PathBuf,
    /// Branch being built (default: $GITHUB_REF_NAME)
    #[arg(long)]
    branch: Option<String>,
    /// Repository default branch (default: from $GITHUB_EVENT_PATH)
    #[arg(long)]
    default_branch: Option<String>,
}

#[derive(Subcommand)]
enum KeysAction {
    /// Create a key (prints the plaintext once)
    Create {
        #[arg(long)]
        name: String,
        #[arg(long)]
        scope: Scope,
    },
    /// List keys (name, scope, created_at)
    List,
    /// Revoke a key by name
    Revoke { name: String },
}

/// What snooze and ignore share: which advisory, on which component, where.
#[derive(Args)]
struct OathTarget {
    /// Advisory id (GHSA-..., CVE-...)
    advisory: String,
    /// Service name
    #[arg(long)]
    service: String,
    /// Realm the oath applies to
    #[arg(
        long,
        conflicts_with = "all_realms",
        required_unless_present = "all_realms"
    )]
    realm: Option<String>,
    /// Apply in every realm (same service name)
    #[arg(long)]
    all_realms: bool,
    /// The component's current purl
    #[arg(long)]
    purl: String,
    /// Why this is acceptable
    #[arg(long)]
    reason: String,
}

#[derive(Subcommand)]
enum OathAction {
    /// Snooze an advisory until a date
    Snooze {
        #[command(flatten)]
        target: OathTarget,
        /// First day the oath no longer holds (YYYY-MM-DD, after today UTC)
        #[arg(long)]
        until: NaiveDate,
    },
    /// Ignore an advisory, with a review date (default: 90 days)
    Ignore {
        #[command(flatten)]
        target: OathTarget,
        /// Review date (YYYY-MM-DD)
        #[arg(long)]
        until: Option<NaiveDate>,
    },
    /// List oaths
    List {
        /// active, expired or revoked
        #[arg(long)]
        status: Option<String>,
    },
    /// Revoke an oath
    Revoke { id: i64 },
    /// Move an oath's date; an expired oath becomes active again
    Extend {
        id: i64,
        #[arg(long)]
        until: NaiveDate,
    },
}

fn oath_body(kind: OathKind, t: OathTarget, until: Option<NaiveDate>) -> NewOathBody {
    NewOathBody {
        advisory_id: t.advisory,
        purl: t.purl,
        service: t.service,
        realm: t.realm.unwrap_or_default(),
        all_realms: t.all_realms,
        kind,
        reason: t.reason,
        until,
    }
}

async fn oaths(action: OathAction) -> anyhow::Result<()> {
    let client = Client::from_env()?;
    match action {
        OathAction::Snooze { target, until } => {
            let body = oath_body(OathKind::Snooze, target, Some(until));
            let r: serde_json::Value = client.post_json("/api/v1/oaths", &body).await?;
            println!("oath {}", r["id"]);
        }
        OathAction::Ignore { target, until } => {
            let body = oath_body(OathKind::Ignore, target, until);
            let r: serde_json::Value = client.post_json("/api/v1/oaths", &body).await?;
            println!("oath {}", r["id"]);
        }
        OathAction::List { status } => {
            let path = match status {
                Some(s) => format!("/api/v1/oaths?status={}", Client::encode_segment(&s)),
                None => "/api/v1/oaths".to_string(),
            };
            let all: Vec<Oath> = client.get_json(&path).await?;
            for o in all {
                let due = o
                    .expires_at
                    .or(o.review_at)
                    .map(|d| d.date_naive().to_string());
                println!(
                    "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
                    o.id,
                    o.status,
                    o.advisory_id,
                    o.name_key,
                    o.service_name,
                    o.realm.as_deref().unwrap_or("*"),
                    due.unwrap_or_default(),
                    o.reason
                );
            }
        }
        OathAction::Revoke { id } => {
            let _: Oath = client
                .post_json(
                    &format!("/api/v1/oaths/{id}/revoke"),
                    &serde_json::json!({}),
                )
                .await?;
            println!("revoked oath {id}");
        }
        OathAction::Extend { id, until } => {
            let body = ExtendBody { until };
            let _: Oath = client
                .post_json(&format!("/api/v1/oaths/{id}/extend"), &body)
                .await?;
            println!("extended oath {id} to {until}");
        }
    }
    Ok(())
}

async fn run_gate(args: GateArgs) -> anyhow::Result<GateResponse> {
    use anyhow::Context;
    let branch = args
        .branch
        .or_else(|| {
            std::env::var("GITHUB_REF_NAME")
                .ok()
                .filter(|v| !v.is_empty())
        })
        .context("--branch is required when GITHUB_REF_NAME is not set")?;
    let default_branch = match args.default_branch {
        Some(d) => Some(d),
        None => match std::env::var("GITHUB_EVENT_PATH")
            .ok()
            .filter(|p| !p.is_empty())
        {
            Some(p) => gate::default_branch_from_event(std::path::Path::new(&p))?,
            None => None,
        },
    }
    .context(
        "--default-branch is required when $GITHUB_EVENT_PATH has no repository.default_branch",
    )?;

    let text = std::fs::read_to_string(&args.sbom)
        .with_context(|| format!("reading {}", args.sbom.display()))?;
    let sbom: serde_json::Value = serde_json::from_str(&text)
        .with_context(|| format!("{} is not JSON", args.sbom.display()))?;
    let direct = direct_name_keys(&args.repo_root)?;

    let fail_on = serde_json::to_value(args.fail_on)?;
    let enc = Client::encode_segment;
    let path = format!(
        "/api/v1/gate?service={}&realm={}&branch={}&default_branch={}&fail_on={}",
        enc(&args.service),
        enc(&args.realm),
        enc(&branch),
        enc(&default_branch),
        enc(fail_on.as_str().unwrap_or_default()),
    );
    // The server answers within ~60 s; 120 s leaves room for the upload.
    // A timeout is an error, so it exits 2 like an unreachable server.
    let client = Client::from_env()?.with_timeout(std::time::Duration::from_secs(120))?;
    let body = serde_json::json!({ "sbom": sbom, "direct": direct });
    client.post_json(&path, &body).await
}

fn print_gate(r: &GateResponse) {
    if !r.findings.is_empty() {
        print!("{}", gate::table(&r.findings));
    }
    for purl in &r.unverified {
        println!("unverified: {purl}");
    }
    let verdict = serde_json::to_value(r.verdict).unwrap_or_default();
    let source = serde_json::to_value(r.source).unwrap_or_default();
    println!(
        "hofund: {} (checked against {})",
        verdict.as_str().unwrap_or("?"),
        source.as_str().unwrap_or("?")
    );
}

async fn keys(action: KeysAction) -> anyhow::Result<()> {
    let client = Client::from_env()?;
    match action {
        KeysAction::Create { name, scope } => {
            let body = CreateKeyRequest { name, scope };
            let r: CreateKeyResponse = client.post_json("/api/v1/keys", &body).await?;
            println!("{}", r.key);
        }
        KeysAction::List => {
            let keys: Vec<KeyInfo> = client.get_json("/api/v1/keys").await?;
            for k in keys {
                println!("{}\t{}\t{}", k.name, k.scope, k.created_at.to_rfc3339());
            }
        }
        KeysAction::Revoke { name } => {
            client
                .delete(&format!("/api/v1/keys/{}", Client::encode_segment(&name)))
                .await?;
            println!("revoked {name}");
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Serve {
            check_config: true,
            config,
        } => {
            let path = config.unwrap_or_else(|| PathBuf::from("heimdall.yaml"));
            match HeimdallConfig::load(&path) {
                Ok(_) => {
                    println!("config ok");
                    ExitCode::SUCCESS
                }
                Err(e) => {
                    eprintln!("config error: {e:#}");
                    ExitCode::FAILURE
                }
            }
        }
        Command::Gate(args) => match run_gate(args).await {
            Ok(r) => {
                print_gate(&r);
                ExitCode::from(gate::exit_code(r.verdict))
            }
            // Unreachable server, HTTP error or bad input: the build cannot be
            // vouched for, which is "unverified", never "pass".
            Err(e) => {
                eprintln!("hofund: {e:#}");
                ExitCode::from(2)
            }
        },
        Command::Keys { action } => match keys(action).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e:#}");
                ExitCode::FAILURE
            }
        },
        Command::Oath { action } => match oaths(action).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e:#}");
                ExitCode::FAILURE
            }
        },
        _ => {
            eprintln!("not implemented yet");
            ExitCode::FAILURE
        }
    }
}
