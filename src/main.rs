use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use heimdall::auth::{CreateKeyRequest, CreateKeyResponse, KeyInfo, Scope};
use heimdall::client::Client;
use heimdall::config::HeimdallConfig;

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
    Oath,
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
            client.delete(&format!("/api/v1/keys/{name}")).await?;
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
        _ => {
            eprintln!("not implemented yet");
            ExitCode::FAILURE
        }
    }
}
