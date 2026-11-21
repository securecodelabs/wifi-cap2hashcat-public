//! Offline, conservative RSN-PSK capture conversion to Hashcat mode 22000.
mod capture;
mod frame;
mod matcher;

use anyhow::{Result, ensure};
pub use capture::EmbeddedMetadata;
pub use frame::{Cipher, Mac, SecurityProfile};
use frame::{Event, Group, KeyFrame};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet};

pub const MAX_INPUT_BYTES: usize = 256 * 1024 * 1024;
const MAX_KEY_FRAMES: usize = 65_536;
const MAX_FRAMES_PER_CONVERSATION: usize = 2048;
const MAX_SSID_ENTRIES: usize = 65_536;
type Names = BTreeMap<(u64, Mac), BTreeSet<Vec<u8>>>;

#[derive(Clone, Debug)]
pub struct Config {
    pub bssid: Option<Mac>,
    /// Explicit SSID for the selected BSSID; requires bssid to be set.
    pub ssid: Option<Vec<u8>>,
    pub timeout_ms: u64,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            bssid: None,
            ssid: None,
            timeout_ms: 5000,
        }
    }
}

#[derive(Debug, Serialize)]
pub struct Export {
    pub ap: String,
    pub station: String,
    pub ssid_hex: String,
    pub stream: u64,
    pub m2_packet: u64,
    pub peer_packet: u64,
    pub message_pair: String,
    pub security_profile: SecurityProfile,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub format: String,
    pub input_bytes: usize,
    pub packets: u64,
    /// Accepted RSN descriptor-version-1/2 pairwise key frames, indexed M1..M4.
    pub key_messages: [u64; 4],
    pub skipped_packets: BTreeMap<String, u64>,
    pub skipped_m2: BTreeMap<String, u64>,
    pub duplicate_exports: u64,
    pub timeout_ms: u64,
    pub selected_bssid: Option<String>,
    pub ssid_override_hex: Option<String>,
    pub validation: &'static str,
    pub exports: Vec<Export>,
    /// Recorder provenance only; never substitutes for captured evidence.
    pub embedded_metadata: Vec<EmbeddedMetadata>,
}

#[derive(Debug)]
pub struct Conversion {
    pub hashes: Vec<String>,
    pub report: Report,
}
pub(crate) fn count(map: &mut BTreeMap<String, u64>, reason: &str) {
    *map.entry(reason.to_owned()).or_default() += 1;
}

/// Converts a complete capture without I/O or password recovery.
/// A malformed container or exceeded resource limit fails the whole conversion.
/// Malformed/unsupported radio packets are counted and skipped.
pub fn convert(input: &[u8], config: &Config) -> Result<Conversion> {
    ensure!(
        input.len() <= MAX_INPUT_BYTES,
        "Input exceeds the 256 MiB limit"
    );
    ensure!(
        (1..=60_000).contains(&config.timeout_ms),
        "timeout-ms must be between 1 and 60000"
    );
    if let Some(ssid) = &config.ssid {
        ensure!(config.bssid.is_some(), "An SSID override requires --bssid");
        ensure!(
            (1..=32).contains(&ssid.len()),
            "SSID must contain 1..32 bytes"
        );
    }
    if let Some(ap) = config.bssid {
        ensure!(
            ap != [0; 6] && ap[0] & 1 == 0,
            "BSSID must be a nonzero unicast address"
        );
    }
    let mut report = Report {
        format: String::new(),
        input_bytes: input.len(),
        packets: 0,
        key_messages: [0; 4],
        skipped_packets: BTreeMap::new(),
        skipped_m2: BTreeMap::new(),
        duplicate_exports: 0,
        timeout_ms: config.timeout_ms,
        selected_bssid: config.bssid.map(hex::encode),
        ssid_override_hex: config.ssid.as_ref().map(hex::encode),
        validation: "structural_only",
        exports: Vec::new(),
        embedded_metadata: Vec::new(),
    };
    let mut names = Names::new();
    let mut groups = BTreeMap::<Group, Vec<KeyFrame>>::new();
    let mut key_count = 0usize;
    let mut name_count = 0usize;
    let mut embedded_metadata = Vec::new();
    let format = capture::decode(
        input,
        |packet| {
            report.packets += 1;
            match frame::parse(&packet) {
                Ok(Some(Event::Ssid { ap, name })) => {
                    if config.bssid.is_none_or(|target| target == ap)
                        && names.entry((packet.stream, ap)).or_default().insert(name)
                    {
                        name_count += 1;
                        ensure!(
                            name_count <= MAX_SSID_ENTRIES,
                            "SSID context limit exceeded (65536)"
                        );
                    }
                }
                Ok(Some(Event::Key(key))) => {
                    if config.bssid.is_some_and(|target| target != key.group.ap) {
                        count(&mut report.skipped_packets, "bssid_filter");
                    } else {
                        report.key_messages[usize::from(key.message - 1)] += 1;
                        key_count += 1;
                        ensure!(
                            key_count <= MAX_KEY_FRAMES,
                            "Key frame limit exceeded (65536)"
                        );
                        let group = groups.entry(key.group.clone()).or_default();
                        ensure!(
                            group.len() < MAX_FRAMES_PER_CONVERSATION,
                            "Key frame limit exceeded for one AP/client/interface (2048)"
                        );
                        group.push(key);
                    }
                }
                Ok(None) => count(&mut report.skipped_packets, "irrelevant_or_hidden_ssid"),
                Err(reason) => count(&mut report.skipped_packets, reason),
            }
            Ok(())
        },
        &mut embedded_metadata,
    )?;
    report.embedded_metadata = embedded_metadata;
    report.format = format.to_owned();
    let hashes = matcher::extract(groups, &names, config, &mut report);
    Ok(Conversion { hashes, report })
}
