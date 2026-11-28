mod containers;
mod frames;
mod pattern;

use anyhow::{Result, bail, ensure};
use clap::ValueEnum;
use serde::Serialize;
use std::path::Path;

#[derive(Clone, Copy, Debug, ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum CaptureFormat {
    Pcap,
    Pcapng,
}

impl CaptureFormat {
    pub fn from_path(path: &Path) -> Result<Self> {
        match path
            .extension()
            .and_then(|value| value.to_str())
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("pcap") => Ok(Self::Pcap),
            Some("pcapng") => Ok(Self::Pcapng),
            _ => bail!("Use a .pcap/.pcapng output name or supply --format"),
        }
    }
}

#[derive(Clone, Copy, Debug, ValueEnum, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum Handshake {
    Full,
    #[value(name = "m1-m2")]
    #[serde(rename = "m1-m2")]
    M1M2,
    #[value(name = "m2-m3")]
    #[serde(rename = "m2-m3")]
    M2M3,
    #[value(name = "m2-only")]
    #[serde(rename = "m2-only")]
    M2Only,
}

impl Handshake {
    pub fn messages(self) -> &'static [u8] {
        match self {
            Self::Full => &[1, 2, 3, 4],
            Self::M1M2 => &[1, 2],
            Self::M2M3 => &[2, 3],
            Self::M2Only => &[2],
        }
    }
    pub fn recoverable(self) -> bool {
        !matches!(self, Self::M2Only)
    }
}

pub struct Generated {
    pub capture: Vec<u8>,
    pub pattern: String,
    pub candidate_count: u64,
}

pub fn generate(
    ssid: &str,
    password: &str,
    handshake: Handshake,
    format: CaptureFormat,
    unknown: u8,
) -> Result<Generated> {
    ensure!(
        (1..=32).contains(&ssid.len()),
        "SSID must contain 1..32 UTF-8 bytes"
    );
    ensure!(
        (8..=63).contains(&password.len()) && password.bytes().all(|b| (32..=126).contains(&b)),
        "Password must contain 8..63 printable ASCII bytes"
    );
    let (pattern, candidate_count) = pattern::suggest(password, usize::from(unknown))?;
    let mut packets = vec![(0, frames::beacon(ssid.as_bytes()))];
    let exchange = frames::exchange(ssid.as_bytes(), password.as_bytes())?;
    for &message in handshake.messages() {
        packets.push((
            u32::from(message) * 1000,
            exchange[usize::from(message - 1)].clone(),
        ));
    }
    let capture = match format {
        CaptureFormat::Pcap => containers::pcap(&packets),
        CaptureFormat::Pcapng => containers::pcapng(&packets),
    };
    Ok(Generated {
        capture,
        pattern,
        candidate_count,
    })
}
