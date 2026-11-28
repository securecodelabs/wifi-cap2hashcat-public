//! Offline synthetic fixtures; this executable never captures or transmits traffic.
#[path = "../synthetic/mod.rs"]
mod synthetic;

use anyhow::{Context, Result, ensure};
use clap::Parser;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use synthetic::{CaptureFormat, Handshake};

#[derive(Parser)]
#[command(
    version,
    about = "Generate deterministic synthetic WPA2-PSK PCAP/PCAPNG test captures"
)]
struct Args {
    /// New capture file. Existing files are never overwritten.
    #[arg(short, long)]
    output: PathBuf,
    /// Known test passphrase: 8..63 printable ASCII bytes.
    #[arg(long)]
    password: String,
    #[arg(long, default_value = "synthetic-wifi-lab")]
    ssid: String,
    /// Infer from .pcap/.pcapng when omitted.
    #[arg(long, value_enum)]
    format: Option<CaptureFormat>,
    #[arg(long, value_enum, default_value = "full")]
    handshake: Handshake,
    /// Wildcard this many trailing password bytes in the suggested GPU mask.
    #[arg(long, default_value_t = 4, value_parser = clap::value_parser!(u8).range(0..=8))]
    unknown_suffix: u8,
    /// Print a machine-readable summary including the known test password.
    #[arg(long)]
    json: bool,
}

fn save(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path).with_context(|| {
        format!(
            "Cannot create {}; existing outputs are preserved",
            path.display()
        )
    })?;
    Ok(())
}

fn run(args: Args) -> Result<()> {
    let format = args
        .format
        .map(Ok)
        .unwrap_or_else(|| CaptureFormat::from_path(&args.output))?;
    let generated = synthetic::generate(
        &args.ssid,
        &args.password,
        args.handshake,
        format,
        args.unknown_suffix,
    )?;
    ensure!(
        args.output.file_name().is_some(),
        "Output needs a file name"
    );
    save(&args.output, &generated.capture)?;
    let summary = serde_json::json!({
        "schema_version": 1, "synthetic": true, "output": args.output,
        "format": format, "handshake": args.handshake, "ssid": args.ssid,
        "password": args.password, "password_hex": hex::encode(args.password.as_bytes()),
        "packet_count": args.handshake.messages().len() + 1,
        "eapol_messages": args.handshake.messages(), "recoverable": args.handshake.recoverable(),
        "pattern": generated.pattern, "candidate_count": generated.candidate_count,
        "security": "WPA2-PSK / CCMP-128 / HMAC-SHA1"
    });
    let mut stdout = std::io::stdout().lock();
    if args.json {
        serde_json::to_writer_pretty(&mut stdout, &summary)?;
        writeln!(stdout)?;
    } else {
        writeln!(stdout, "Synthetic capture: {}", summary["output"])?;
        writeln!(stdout, "EAPOL messages: {}", summary["eapol_messages"])?;
        writeln!(stdout, "Known test password: {}", summary["password"])?;
        writeln!(stdout, "WiFi GPU --mask: {}", summary["pattern"])?;
        writeln!(stdout, "Candidates: {}", summary["candidate_count"])?;
        if !args.handshake.recoverable() {
            writeln!(
                stdout,
                "Negative fixture: M2 alone has no AP nonce; no recoverable HC22000 pair is expected."
            )?;
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("Error: {error:#}");
            ExitCode::FAILURE
        }
    }
}
