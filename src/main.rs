use std::path::PathBuf;
use std::process::ExitCode;

use chrono::NaiveDate;
use clap::{Args, Parser, Subcommand};
use heimdall::auth::{CreateKeyRequest, CreateKeyResponse, KeyInfo, Scope};
use heimdall::client::Client;
use heimdall::config::HeimdallConfig;
use heimdall::model::OathKind;
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
    /// Hofund: CI gate
    Gate,
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
