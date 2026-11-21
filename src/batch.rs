use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use wifi_cap2hashcat::Config;

const MAX_METADATA_BYTES: u64 = 1024 * 1024;

/// Optional provenance only. These values never replace captured packet data.
#[derive(Serialize)]
pub(crate) struct Metadata {
    source: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    warning: Option<String>,
}

struct Job {
    input: PathBuf,
    output: PathBuf,
    report: PathBuf,
}

fn name_key(path: &Path) -> String {
    path.file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_lowercase()
}

fn read_metadata(path: &Path) -> Result<serde_json::Value> {
    // Do not follow sidecar symlinks or read directories/devices as metadata.
    ensure!(
        fs::symlink_metadata(path)?.file_type().is_file(),
        "Metadata must be a regular file (not a symlink)"
    );
    let file = File::open(path)?;
    ensure!(
        file.metadata()?.is_file(),
        "Metadata must be a regular file"
    );
    let mut bytes = Vec::new();
    file.take(MAX_METADATA_BYTES + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= MAX_METADATA_BYTES,
        "Metadata exceeds the 1 MiB limit"
    );
    let bytes = bytes.strip_prefix(b"\xef\xbb\xbf").unwrap_or(&bytes);
    let value: serde_json::Value = serde_json::from_slice(bytes)?;
    ensure!(value.is_object(), "Metadata must be a JSON object");
    Ok(value)
}

fn metadata_for(input: &Path, entries: &BTreeMap<String, Vec<PathBuf>>) -> Option<Metadata> {
    // Prefer the formats emitted by both of our recorders, then basename.json.
    let primary = format!("{}.json", name_key(input));
    let fallback = name_key(&input.with_extension("json"));
    let paths = entries.get(&primary).or_else(|| entries.get(&fallback))?;
    let path = &paths[0];
    let result = if paths.len() == 1 {
        read_metadata(path)
    } else {
        Err(anyhow::anyhow!(
            "Ambiguous sidecar filenames differing only in case"
        ))
    };
    let (data, warning) = match result {
        Ok(value) => (Some(value), None),
        Err(error) => {
            let warning = format!("{error:#}");
            eprintln!(
                "warning: {}: ignoring metadata: {}",
                path.display(),
                warning
            );
            (None, Some(warning))
        }
    };
    Some(Metadata {
        source: path.display().to_string(),
        data,
        warning,
    })
}

pub(crate) fn run(
    directory: &Path,
    output_dir: Option<&Path>,
    config: &Config,
    overwrite: bool,
) -> Result<ExitCode> {
    ensure!(
        directory.is_dir(),
        "Not a directory: {}",
        directory.display()
    );
    let output_directory = output_dir.unwrap_or(directory);
    if output_dir.is_some() {
        ensure!(
            !output_directory.as_os_str().is_empty(),
            "Output directory must not be empty"
        );
        fs::create_dir_all(output_directory)
            .with_context(|| format!("Create output directory {}", output_directory.display()))?;
    }
    let mut entries = BTreeMap::<String, Vec<PathBuf>>::new();
    let mut jobs = Vec::new();
    for entry in fs::read_dir(directory)
        .with_context(|| format!("Read directory {}", directory.display()))?
    {
        let entry = entry?;
        let path = entry.path();
        entries
            .entry(name_key(&path))
            .or_default()
            .push(path.clone());
        if !entry.file_type()?.is_file() {
            continue;
        }
        let capture = path
            .extension()
            .and_then(|v| v.to_str())
            .is_some_and(|ext| {
                ext.eq_ignore_ascii_case("pcap") || ext.eq_ignore_ascii_case("pcapng")
            });
        if capture {
            let base = output_directory.join(entry.file_name());
            jobs.push(Job {
                output: base.with_extension("hc22000"),
                report: base.with_extension("conversion.json"),
                input: path,
            });
        }
    }
    jobs.sort_by(|a, b| a.input.cmp(&b.input));

    // A report for one job can share a name with another capture's sidecar.
    // Protect every capture and both matching sidecar names across the batch.
    let mut protected = BTreeSet::new();
    for job in &jobs {
        protected.insert(super::path_key(&job.input)?);
        for key in [
            format!("{}.json", name_key(&job.input)),
            name_key(&job.input.with_extension("json")),
        ] {
            if let Some(paths) = entries.get(&key) {
                for path in paths {
                    protected.insert(super::path_key(path)?);
                }
            }
        }
    }

    // Preflight the whole set so equal basenames cannot arbitrarily choose a winner.
    // Case folding also protects results when the same directory is copied to Windows.
    let mut outputs = BTreeMap::<String, usize>::new();
    for job in &jobs {
        *outputs.entry(name_key(&job.output)).or_default() += 1;
    }
    let total = jobs.len();
    let (mut converted, mut no_pair, mut failed, mut sidecars) = (0, 0, 0, 0);
    for job in jobs {
        if outputs[&name_key(&job.output)] != 1 {
            eprintln!(
                "error: {}: output basename collision at {}; rename the captures",
                job.input.display(),
                job.output.display()
            );
            failed += 1;
            continue;
        }
        let metadata = metadata_for(&job.input, &entries);
        sidecars += usize::from(metadata.is_some());
        if let Some(info) = &metadata {
            eprintln!("{}: metadata {}", job.input.display(), info.source);
        }
        match super::convert_file(
            &job.input,
            Some(&job.output),
            Some(&job.report),
            config,
            metadata.as_ref(),
            overwrite,
            &protected,
        ) {
            Ok(true) => {
                converted += 1;
                eprintln!("Saved {}", job.output.display());
            }
            Ok(false) => no_pair += 1,
            Err(error) => {
                failed += 1;
                eprintln!("error: {}: {error:#}", job.input.display());
            }
        }
    }
    eprintln!(
        "Batch: {total} capture(s); {converted} converted; {no_pair} without eligible pairs; {failed} failed; {sidecars} matching JSON sidecar(s)"
    );
    if total == 0 {
        eprintln!("No .pcap or .pcapng files found (directory mode is not recursive).");
    }
    Ok(if failed > 0 {
        ExitCode::FAILURE
    } else if total == 0 || no_pair > 0 {
        ExitCode::from(2)
    } else {
        ExitCode::SUCCESS
    })
}
