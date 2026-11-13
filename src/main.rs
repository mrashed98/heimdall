use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
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
    Keys,
    /// Sight: inventory scanning
    Sight,
    /// Generate SBOMs for images that have none
    ScanImages,
    /// Realms
    Realms,
}

fn main() -> ExitCode {
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
        _ => {
            eprintln!("not implemented yet");
            ExitCode::FAILURE
        }
    }
}
