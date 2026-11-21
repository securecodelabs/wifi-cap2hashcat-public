mod batch;

use anyhow::{Context, Result, ensure};
use clap::Parser;
use serde::Serialize;
use std::collections::BTreeSet;
use std::fs::File;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use wifi_cap2hashcat::{Config, MAX_INPUT_BYTES, Mac, convert};

#[derive(Parser)]
#[command(
    version,
    about = "Convert offline WPA2-PSK PCAP or PCAPNG captures to Hashcat mode 22000"
)]
struct Args {
    /// Input capture or directory. Capture magic bytes determine the format.
    #[arg(required_unless_present = "directory", conflicts_with = "directory")]
    input: Option<PathBuf>,
    /// Convert all PCAP/PCAPNG files in a directory (not recursive).
    #[arg(long, conflicts_with_all = ["input", "output", "report"])]
    directory: Option<PathBuf>,
    /// Save batch hashes and reports in this directory; create it if needed.
    #[arg(long, conflicts_with_all = ["output", "report"])]
    output_dir: Option<PathBuf>,
    /// Output file; defaults to stdout. Existing files require --overwrite.
    #[arg(short, long)]
    output: Option<PathBuf>,
    /// Write a JSON conversion report. Existing files require --overwrite.
    #[arg(long)]
    report: Option<PathBuf>,
    /// Replace existing hash and conversion report files (never input captures/metadata).
    #[arg(long)]
    overwrite: bool,
    /// Only export this AP (colon-separated or 12 hex digits).
    #[arg(long, value_parser = parse_mac)]
    bssid: Option<Mac>,
    /// Explicit UTF-8 SSID for the selected BSSID.
    #[arg(long, requires = "bssid", conflicts_with = "ssid_hex")]
    ssid: Option<String>,
    /// Explicit SSID bytes as hex, for a hidden or non-UTF-8 name.
    #[arg(long, requires = "bssid")]
    ssid_hex: Option<String>,
    /// Maximum M1/M2 or M2/M3 interval in milliseconds (1..60000).
    #[arg(long, default_value_t = 5000, value_parser = clap::value_parser!(u64).range(1..=60_000))]
    timeout_ms: u64,
}
fn parse_mac(value: &str) -> std::result::Result<Mac, String> {
    let compact = if value.contains(':') {
        let parts: Vec<_> = value.split(':').collect();
        if parts.len() != 6 || parts.iter().any(|p| p.len() != 2) {
            return Err("Use six two-digit hex bytes separated by colons".into());
        }
        parts.join("")
    } else {
        value.to_owned()
    };
    let mut mac = [0; 6];
    hex::decode_to_slice(compact, &mut mac).map_err(|_| "Invalid BSSID hex".to_owned())?;
    if mac == [0; 6] || mac[0] & 1 != 0 {
        return Err("BSSID must be a nonzero unicast address".into());
    }
    Ok(mac)
}
fn parent(path: &Path) -> &Path {
    path.parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."))
}
fn check_destination(path: &Path, overwrite: bool) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                overwrite,
                "Refusing to overwrite {}; use --overwrite to replace generated files",
                path.display()
            );
            ensure!(
                metadata.file_type().is_file(),
                "Refusing to replace non-regular output (directory or symlink): {}",
                path.display()
            );
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("Inspect {}", path.display())),
    }
    Ok(())
}
fn destination(path: &Path, overwrite: bool) -> Result<PathBuf> {
    check_destination(path, overwrite)?;
    let folder = parent(path).canonicalize().with_context(|| {
        format!(
            "Output directory does not exist: {}",
            parent(path).display()
        )
    })?;
    ensure!(folder.is_dir(), "Output parent must be a directory");
    Ok(folder.join(path.file_name().context("Output path needs a file name")?))
}
fn path_key(path: &Path) -> Result<String> {
    let absolute = path
        .canonicalize()
        .or_else(|_| {
            parent(path)
                .canonicalize()
                .map(|folder| folder.join(path.file_name().unwrap_or_default()))
        })
        .with_context(|| format!("Resolve {}", path.display()))?;
    // Windows aliases and case changes must not let an output replace its input.
    Ok(absolute.to_string_lossy().to_lowercase())
}
fn prepare(path: &Path, bytes: &[u8]) -> Result<tempfile::NamedTempFile> {
    let mut temp = tempfile::NamedTempFile::new_in(parent(path))?;
    temp.write_all(bytes)?;
    temp.as_file().sync_all()?;
    Ok(temp)
}
fn publish(temp: tempfile::NamedTempFile, path: &Path, overwrite: bool) -> Result<()> {
    check_destination(path, overwrite)?;
    let result = if overwrite {
        temp.persist(path)
    } else {
        temp.persist_noclobber(path)
    };
    result
        .map_err(|e| e.error)
        .with_context(|| format!("Publish {}", path.display()))?;
    Ok(())
}

fn convert_file(
    input: &Path,
    output: Option<&Path>,
    report_path: Option<&Path>,
    config: &Config,
    metadata: Option<&batch::Metadata>,
    overwrite: bool,
    protected: &BTreeSet<String>,
) -> Result<bool> {
    let output = output.map(|p| destination(p, overwrite)).transpose()?;
    let report_path = report_path.map(|p| destination(p, overwrite)).transpose()?;
    let input_key = path_key(input)?;
    for path in output.iter().chain(report_path.iter()) {
        let key = path_key(path)?;
        ensure!(
            key != input_key && !protected.contains(&key),
            "Refusing to replace input capture or metadata: {}",
            path.display()
        );
    }
    if let (Some(a), Some(b)) = (&output, &report_path) {
        // Windows paths are usually case-insensitive; a conservative check is safe elsewhere.
        ensure!(
            path_key(a)? != path_key(b)?,
            "Output and report must be different paths"
        );
    }
    // Opening a FIFO can block indefinitely before the handle can be inspected.
    ensure!(
        std::fs::metadata(input)
            .with_context(|| format!("Inspect {}", input.display()))?
            .is_file(),
        "Input must be a regular file"
    );
    let file = File::open(input).with_context(|| format!("Open {}", input.display()))?;
    ensure!(file.metadata()?.is_file(), "Input must be a regular file");
    let mut bytes = Vec::new();
    file.take(MAX_INPUT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    let converted = convert(&bytes, config)?;
    #[derive(Serialize)]
    struct Document<'a> {
        converter_version: &'static str,
        source: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        capture_metadata: Option<&'a batch::Metadata>,
        #[serde(flatten)]
        report: &'a wifi_cap2hashcat::Report,
    }
    let report_bytes = if report_path.is_some() {
        let mut data = serde_json::to_vec_pretty(&Document {
            converter_version: env!("CARGO_PKG_VERSION"),
            source: input.display().to_string(),
            capture_metadata: metadata,
            report: &converted.report,
        })?;
        data.push(b'\n');
        Some(data)
    } else {
        None
    };
    let report_temp = report_path
        .as_ref()
        .zip(report_bytes.as_ref())
        .map(|(path, data)| prepare(path, data))
        .transpose()?;
    let count = converted.hashes.len();
    if count != 0 {
        let text = converted.hashes.join("\n") + "\n";
        if let Some(path) = &output {
            let temp = prepare(path, text.as_bytes())?;
            publish(temp, path, overwrite)?;
        } else {
            std::io::stdout().lock().write_all(text.as_bytes())?;
        }
    }
    if let Some((temp, path)) = report_temp.zip(report_path.as_ref()) {
        publish(temp, path, overwrite)?;
    }
    eprintln!(
        "{}: {}: {} packets; M1/M2/M3/M4 {:?}; {} hash(es); validation=structural_only",
        input.display(),
        converted.report.format,
        converted.report.packets,
        converted.report.key_messages,
        count
    );
    for (reason, number) in &converted.report.skipped_packets {
        if reason != "irrelevant_or_hidden_ssid" {
            eprintln!("  skipped packets: {reason}={number}");
        }
    }
    for (reason, number) in &converted.report.skipped_m2 {
        eprintln!("  skipped M2: {reason}={number}");
    }
    if count == 0 {
        eprintln!("No eligible WPA2-PSK message pair found; no hash file written.");
        if let Some(path) = output.filter(|path| path.exists()) {
            eprintln!(
                "warning: previous hash file left unchanged: {}",
                path.display()
            );
        }
    }
    Ok(count != 0)
}

fn run(args: Args) -> Result<ExitCode> {
    let ssid = match (args.ssid, args.ssid_hex) {
        (Some(s), _) => Some(s.into_bytes()),
        (_, Some(h)) => Some(hex::decode(h).context("Invalid --ssid-hex")?),
        _ => None,
    };
    if let Some(name) = &ssid {
        ensure!(
            (1..=32).contains(&name.len()),
            "SSID must contain 1..32 bytes"
        );
    }
    let config = Config {
        bssid: args.bssid,
        ssid,
        timeout_ms: args.timeout_ms,
    };
    if let Some(directory) = args.directory {
        return batch::run(
            &directory,
            args.output_dir.as_deref(),
            &config,
            args.overwrite,
        );
    }
    let input = args
        .input
        .context("Supply an input capture or --directory")?;
    if input.is_dir() {
        ensure!(
            args.output.is_none() && args.report.is_none(),
            "Directory mode names its outputs automatically; omit --output and --report"
        );
        return batch::run(&input, args.output_dir.as_deref(), &config, args.overwrite);
    }
    ensure!(
        args.output_dir.is_none(),
        "--output-dir requires directory input; use --output for a single capture"
    );
    let mut protected = BTreeSet::new();
    let mut sidecar = input.as_os_str().to_os_string();
    sidecar.push(".json");
    for path in [PathBuf::from(sidecar), input.with_extension("json")] {
        if path.exists() {
            protected.insert(path_key(&path)?);
        }
    }
    let exported = convert_file(
        &input,
        args.output.as_deref(),
        args.report.as_deref(),
        &config,
        None,
        args.overwrite,
        &protected,
    )?;
    Ok(if exported {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    })
}
fn main() -> ExitCode {
    match run(Args::parse()) {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::FAILURE
        }
    }
}
