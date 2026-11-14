use std::io::IsTerminal;
use std::path::PathBuf;
use std::process::ExitCode;

use chrono::NaiveDate;
use clap::{Args, CommandFactory, FromArgMatches, Parser, Subcommand};
use heimdall::auth::{CreateKeyRequest, CreateKeyResponse, KeyInfo, Scope};
use heimdall::client::Client;
use heimdall::config::HeimdallConfig;
use heimdall::gate::{self, GateResponse};
use heimdall::ingest::manifests::direct_name_keys;
use heimdall::inventory::sight;
use heimdall::model::{OathKind, Severity};
use heimdall::oath::{ExtendBody, NewOathBody, Oath};
use heimdall::scan_images;
use heimdall::server::{FindingRow, RealmRow};
use heimdall::ui::{banner, render, Style};
use heimdall::AppState;

#[derive(Parser)]
#[command(
    name = "heimdall",
    version,
    about = "Vulnerability and release tracker"
)]
struct Cli {
    /// Turn off colour (also: NO_COLOR, TERM=dumb)
    #[arg(long, global = true)]
    no_color: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

/// Parse the command line with the banner above `--help`. The banner has to
/// be chosen before clap runs, so `--no-color` is looked for in the raw args.
fn parse_cli() -> Cli {
    let no_color = std::env::args().any(|a| a == "--no-color");
    let banner_text = banner::render(&Style::detect(no_color), "");
    let matches = Cli::command().before_help(banner_text).get_matches();
    Cli::from_arg_matches(&matches).unwrap_or_else(|e| e.exit())
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
    /// Sight: scan the cluster and ingest its inventory
    Sight(SightArgs),
    /// Generate SBOMs for images that have none
    ScanImages(ScanImagesArgs),
    /// Findings (open by default)
    Findings(FindingsArgs),
    /// Realms, with their service and open-finding counts
    Realms,
}

#[derive(Args)]
struct FindingsArgs {
    #[arg(long)]
    realm: Option<String>,
    /// open or resolved
    #[arg(long, default_value = "open")]
    status: String,
    /// vuln, fixavailable, majorrelease, oathexpired, eol, k8scve, releasenotecve
    #[arg(long)]
    kind: Option<String>,
    /// Lowest severity to list
    #[arg(long)]
    min_severity: Option<String>,
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
    /// Accept an SBOM with no components (otherwise the server rejects it)
    #[arg(long)]
    allow_empty: bool,
}

#[derive(Args)]
struct ScanImagesArgs {
    /// Most images to scan in one run
    #[arg(long, default_value_t = 20)]
    max: usize,
    /// Path to the syft binary
    #[arg(long, default_value = "syft")]
    syft: PathBuf,
}

#[derive(Args)]
struct SightArgs {
    /// Realm the cluster belongs to
    #[arg(long)]
    realm: String,
    /// POST to this Bifröst instead of ingesting in-process (scout mode;
    /// needs HEIMDALL_API_KEY)
    #[arg(long)]
    push: Option<String>,
    /// Path to heimdall.yaml (in-process mode)
    #[arg(long, default_value = "heimdall.yaml")]
    config: PathBuf,
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

async fn oaths(action: OathAction, style: &Style) -> anyhow::Result<()> {
    let client = Client::from_env()?;
    match action {
        OathAction::Snooze { target, until } => {
            let body = oath_body(OathKind::Snooze, target, Some(until));
            let r: serde_json::Value = client.post_json("/api/v1/oaths", &body).await?;
            print_created(&r, style);
        }
        OathAction::Ignore { target, until } => {
            let body = oath_body(OathKind::Ignore, target, until);
            let r: serde_json::Value = client.post_json("/api/v1/oaths", &body).await?;
            print_created(&r, style);
        }
        OathAction::List { status } => {
            let path = match status {
                Some(s) => format!("/api/v1/oaths?status={}", Client::encode_segment(&s)),
                None => "/api/v1/oaths".to_string(),
            };
            let all: Vec<Oath> = client.get_json(&path).await?;
            print!("{}", render::oaths_table(style, &all));
        }
        OathAction::Revoke { id } => {
            let _: Oath = client
                .post_json(
                    &format!("/api/v1/oaths/{id}/revoke"),
                    &serde_json::json!({}),
                )
                .await?;
            print!("{}", render::ok_line(style, &format!("revoked oath {id}")));
        }
        OathAction::Extend { id, until } => {
            let body = ExtendBody { until };
            let _: Oath = client
                .post_json(&format!("/api/v1/oaths/{id}/extend"), &body)
                .await?;
            print!(
                "{}",
                render::ok_line(style, &format!("extended oath {id} to {until}"))
            );
        }
    }
    Ok(())
}

/// The new oath's id, and the server's warning when it could not tell
/// which advisory the id names.
fn print_created(r: &serde_json::Value, style: &Style) {
    println!("oath {}", r["id"]);
    if let Some(w) = r["warning"].as_str() {
        eprint!("{}", render::warn_line(style, w));
    }
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
    let mut path = format!(
        "/api/v1/gate?service={}&realm={}&branch={}&default_branch={}&fail_on={}",
        enc(&args.service),
        enc(&args.realm),
        enc(&branch),
        enc(&default_branch),
        enc(fail_on.as_str().unwrap_or_default()),
    );
    if args.allow_empty {
        path.push_str("&allow_empty=true");
    }
    // The server answers within ~60 s; 120 s leaves room for the upload.
    // A timeout is an error, so it exits 2 like an unreachable server.
    let client = Client::from_env()?.with_timeout(std::time::Duration::from_secs(120))?;
    let body = serde_json::json!({ "sbom": sbom, "direct": direct });
    client.post_json(&path, &body).await
}

async fn sight(args: SightArgs, style: &Style) -> anyhow::Result<()> {
    use anyhow::Context;
    // Without --push the scan is ingested in-process, which needs the config
    // (realm list) and the database.
    let state = match args.push {
        Some(_) => None,
        None => {
            let cfg = HeimdallConfig::load(&args.config)?;
            let url = std::env::var("DATABASE_URL")
                .context("DATABASE_URL is not set (or use --push URL)")?;
            Some(AppState::new(
                heimdall::db::connect(&url).await?,
                std::sync::Arc::new(cfg),
                reqwest::Client::new(),
            ))
        }
    };
    let out = sight::run(state.as_ref(), &args.realm, args.push.as_deref()).await?;
    let msg = format!(
        "sight: {} services, {} components added, {} removed",
        out.services, out.added, out.removed
    );
    print!("{}", render::ok_line(style, &msg));
    Ok(())
}

/// `heimdall findings`: a thin client of `GET /api/v1/findings`.
async fn findings(args: FindingsArgs, style: &Style) -> anyhow::Result<()> {
    let enc = Client::encode_segment;
    let mut path = format!("/api/v1/findings?status={}", enc(&args.status));
    for (name, value) in [
        ("realm", &args.realm),
        ("kind", &args.kind),
        ("min_severity", &args.min_severity),
    ] {
        if let Some(v) = value {
            path.push_str(&format!("&{name}={}", enc(v)));
        }
    }
    let rows: Vec<FindingRow> = Client::from_env()?.get_json(&path).await?;
    print!(
        "{}",
        render::findings_table(style, &rows, &args.status, args.realm.as_deref())
    );
    Ok(())
}

/// `heimdall realms`: a thin client of `GET /api/v1/realms`.
async fn realms(style: &Style) -> anyhow::Result<()> {
    let rows: Vec<RealmRow> = Client::from_env()?.get_json("/api/v1/realms").await?;
    print!("{}", render::realms_table(style, &rows));
    Ok(())
}

async fn keys(action: KeysAction, style: &Style) -> anyhow::Result<()> {
    let client = Client::from_env()?;
    match action {
        KeysAction::Create { name, scope } => {
            let body = CreateKeyRequest { name, scope };
            let r: CreateKeyResponse = client.post_json("/api/v1/keys", &body).await?;
            println!("{}", r.key);
        }
        KeysAction::List => {
            let keys: Vec<KeyInfo> = client.get_json("/api/v1/keys").await?;
            print!("{}", render::keys_table(style, &keys));
        }
        KeysAction::Revoke { name } => {
            client
                .delete(&format!("/api/v1/keys/{}", Client::encode_segment(&name)))
                .await?;
            print!("{}", render::ok_line(style, &format!("revoked {name}")));
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> ExitCode {
    let cli = parse_cli();
    let style = Style::detect(cli.no_color);
    let Some(command) = cli.command else {
        // Bare `heimdall`: banner, then the help text.
        print!("{}", banner::render(&style, ""));
        println!();
        let _ = Cli::command().print_help();
        return ExitCode::SUCCESS;
    };
    match command {
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
        Command::Serve {
            check_config: false,
            config,
        } => {
            let path = config.unwrap_or_else(|| PathBuf::from("heimdall.yaml"));
            // Banner only on a terminal: in k8s stdout is a JSON log stream.
            if std::io::stdout().is_terminal() {
                print!("{}", banner::render(&style, "serving"));
            }
            match heimdall::server::serve(&path).await {
                Ok(()) => ExitCode::SUCCESS,
                Err(e) => {
                    // Telemetry may not be up yet, so this goes to stderr.
                    eprintln!("serve: {e:#}");
                    ExitCode::FAILURE
                }
            }
        }
        Command::Findings(args) => match findings(args, &style).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e:#}");
                ExitCode::FAILURE
            }
        },
        Command::Realms => match realms(&style).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e:#}");
                ExitCode::FAILURE
            }
        },
        Command::Gate(args) => match run_gate(args).await {
            Ok(r) => {
                print!("{}", render::gate_report(&style, &r));
                ExitCode::from(gate::exit_code(r.verdict))
            }
            // Unreachable server, HTTP error or bad input: the build cannot be
            // vouched for, which is "unverified", never "pass".
            Err(e) => {
                eprintln!("hofund: {e:#}");
                ExitCode::from(2)
            }
        },
        Command::Keys { action } => match keys(action, &style).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e:#}");
                ExitCode::FAILURE
            }
        },
        Command::Oath { action } => match oaths(action, &style).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e:#}");
                ExitCode::FAILURE
            }
        },
        Command::Sight(args) => match sight(args, &style).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("error: {e:#}");
                ExitCode::FAILURE
            }
        },
        Command::ScanImages(args) => {
            let report = match Client::from_env() {
                Ok(client) => scan_images::run(&client, &args.syft, args.max).await,
                Err(e) => Err(e),
            };
            match report {
                Ok(r) => {
                    let msg = format!("scan-images: {} scanned, {} failed", r.scanned, r.failed);
                    let line = if r.failed > 0 {
                        render::warn_line(&style, &msg)
                    } else {
                        render::ok_line(&style, &msg)
                    };
                    print!("{line}");
                    // Failure only when every attempted image failed.
                    if r.scanned == 0 && r.failed > 0 {
                        ExitCode::FAILURE
                    } else {
                        ExitCode::SUCCESS
                    }
                }
                Err(e) => {
                    eprintln!("error: {e:#}");
                    ExitCode::FAILURE
                }
            }
        }
    }
}
