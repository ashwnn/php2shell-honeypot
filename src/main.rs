#![forbid(unsafe_code)]
mod capture;
mod evidence;
mod timeline;
mod display;

use anyhow::{bail, Result};
use clap::{Args, Parser, Subcommand, ValueEnum};
use std::{net::IpAddr, path::PathBuf};

#[derive(Parser)]
#[command(version, about = "Inert HTTP decoy and offline HTTP/Cowrie evidence reports")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Serve(Serve),
    /// Read the existing HTTP evidence database; never creates one.
    Report(Report),
    /// Correlate HTTP and Cowrie evidence without contacting any indicator.
    Trace(Trace),
    /// Check that the evidence database is readable (not a listener probe).
    Health { #[arg(long, default_value = "/data")] data: PathBuf },
}

#[derive(Args, Clone)]
pub struct Serve {
    #[arg(long, default_value = "127.0.0.1")]
    host: IpAddr,
    #[arg(long, default_value_t = 8080)]
    port: u16,
    #[arg(long, default_value = "data")]
    data: PathBuf,
    #[arg(long, default_value_t = 16_777_216, value_parser = clap::value_parser!(u32).range(1024..=67_108_864))]
    max_bytes: u32,
    #[arg(long, default_value_t = 4096, value_parser = clap::value_parser!(u32).range(1..))]
    quota_mib: u32,
    #[arg(long, default_value_t = 30, value_parser = clap::value_parser!(u64).range(1..=300))]
    timeout: u64,
    #[arg(long, default_value_t = 4, value_parser = clap::value_parser!(u32).range(1..=256))]
    max_connections: u32,
    #[arg(long, requires = "key")]
    cert: Option<PathBuf>,
    #[arg(long, requires = "cert")]
    key: Option<PathBuf>,
}

#[derive(Args)]
pub struct Report {
    #[arg(long, default_value = "data")]
    data: PathBuf,
    #[arg(long, default_value_t = 10_000, value_parser = clap::value_parser!(u32).range(1..=100_000))]
    limit: u32,
    #[arg(long, default_value_t = 20, value_parser = clap::value_parser!(u32).range(0..=100_000))]
    recent: u32,
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat { Json, Text }

#[derive(Args, Clone)]
pub struct Trace {
    #[arg(long, default_value = "/data")]
    http: PathBuf,
    #[arg(long, default_value = "/cowrie")]
    cowrie: PathBuf,
    /// Additional HTTPS sensor evidence directory.
    #[arg(long)]
    https: Option<PathBuf>,
    #[arg(long)]
    ip: Option<IpAddr>,
    #[arg(long)]
    session: Option<String>,
    #[arg(long, value_parser = timeline::timestamp)]
    since: Option<String>,
    #[arg(long, default_value_t = 10_000, value_parser = clap::value_parser!(u32).range(1..=100_000))]
    limit: u32,
    #[arg(long, default_value_t = 8_388_608, value_parser = clap::value_parser!(u32).range(1..=16_777_216))]
    max_log_bytes: u32,
    #[arg(long, default_value_t = 8, value_parser = clap::value_parser!(u32).range(1..=32))]
    max_files: u32,
    #[arg(long)]
    indicators: bool,
    #[arg(long)]
    show_credentials: bool,
    /// Include per-session commands, logins, duration and recording references.
    #[arg(long)]
    summary: bool,
    /// Emit bounded snapshots as newly observed JSON events every 2 seconds.
    #[arg(long)]
    follow: bool,
    /// JSON for integrations; text for terminal monitoring.
    #[arg(long, value_enum, default_value = "json")]
    format: OutputFormat,
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Serve(args) => capture::serve(args).await,
        Command::Report(args) => evidence::report(args),
        Command::Trace(args) => timeline::run(args).await,
        Command::Health { data } => {
            let db = evidence::open_readonly(&data)?;
            db.query_row("SELECT count(*) FROM sqlite_master WHERE name='events'", [], |r| r.get::<_, i64>(0))
                .and_then(|n| if n == 1 { Ok(()) } else { Err(rusqlite::Error::InvalidQuery) })?;
            if !data.is_dir() { bail!("evidence directory missing"); }
            println!("ok: evidence database readable; listener health unknown");
            Ok(())
        }
    }
}
