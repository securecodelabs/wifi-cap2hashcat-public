use serde_json::Value;
use std::fs;
use std::process::{Command, Output};
use wifi_cap2hashcat::{Config, convert};

fn generator() -> Command {
    Command::new(env!("CARGO_BIN_EXE_wifi-capture-synth"))
}

fn summary(output: Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn both_containers_have_full_partial_and_negative_exchanges() {
    let directory = tempfile::tempdir().unwrap();
    for format in ["pcap", "pcapng"] {
        for (mode, counts, recoverable) in [
            ("full", [1, 1, 1, 1], true),
            ("m1-m2", [1, 1, 0, 0], true),
            ("m2-m3", [0, 1, 1, 0], true),
            ("m2-only", [0, 1, 0, 0], false),
        ] {
            let path = directory.path().join(format!("{mode}.{format}"));
            let info = summary(
                generator()
                    .arg("--output")
                    .arg(&path)
                    .args(["--password", "ABCDEF12", "--handshake", mode, "--json"])
                    .output()
                    .unwrap(),
            );
            assert_eq!(info["format"], format);
            assert_eq!(info["handshake"], mode);
            assert_eq!(info["pattern"], "ABCD?H?H?H?H");
            assert_eq!(info["candidate_count"], 65536);
            assert_eq!(info["recoverable"], recoverable);
            let converted = convert(&fs::read(path).unwrap(), &Config::default()).unwrap();
            assert_eq!(converted.report.key_messages, counts);
            assert_eq!(converted.report.packets, 1 + counts.iter().sum::<u64>());
            assert!(converted.report.skipped_packets.is_empty());
            assert_eq!(converted.hashes.len(), usize::from(recoverable));
            if recoverable {
                assert_eq!(
                    converted.report.exports[0].message_pair,
                    if mode == "m1-m2" { "00" } else { "02" }
                );
            }
        }
    }
}

#[test]
fn passwords_ssids_formats_and_output_conflicts_are_validated() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("test.pcapng");
    for password in ["ABCD", "1234567", &"x".repeat(64), "pass\nword", "pässword"] {
        assert!(
            !generator()
                .arg("--output")
                .arg(&path)
                .args(["--password", password])
                .output()
                .unwrap()
                .status
                .success()
        );
        assert!(!path.exists());
    }
    for ssid in [String::new(), "é".repeat(17)] {
        assert!(
            !generator()
                .arg("--output")
                .arg(&path)
                .args(["--password", "ABCDEF12", "--ssid", &ssid])
                .output()
                .unwrap()
                .status
                .success()
        );
        assert!(!path.exists());
    }
    summary(
        generator()
            .arg("--output")
            .arg(&path)
            .args(["--password", "ABCDEF12", "--json"])
            .output()
            .unwrap(),
    );
    let before = fs::read(&path).unwrap();
    assert!(
        !generator()
            .arg("--output")
            .arg(&path)
            .args(["--password", "OTHER123"])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(fs::read(path).unwrap(), before);
    let unknown = directory.path().join("unknown.data");
    assert!(
        !generator()
            .arg("--output")
            .arg(&unknown)
            .args(["--password", "ABCDEF12"])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert!(!unknown.exists());
    summary(
        generator()
            .arg("--output")
            .arg(&unknown)
            .args(["--password", "ABCDEF12", "--format", "pcap", "--json"])
            .output()
            .unwrap(),
    );
    assert_eq!(&fs::read(unknown).unwrap()[..4], &[0xd4, 0xc3, 0xb2, 0xa1]);
}

#[test]
fn masks_escape_literals_and_report_exact_candidate_counts() {
    let directory = tempfile::tempdir().unwrap();
    for (index, password, unknown, expected, count) in [
        (0, "ABCD?F12", "2", "ABCD??F?d?d", 100),
        (1, "abcdef12", "4", "abcd?h?h?h?h", 65536),
        (2, "ABCDEF12", "0", "ABCDEF12", 1),
        (3, "ABCDEF12", "8", "?H?H?H?H?H?H?H?H", 4294967296_u64),
    ] {
        let info = summary(
            generator()
                .arg("--output")
                .arg(directory.path().join(format!("{index}.pcap")))
                .args([
                    "--password",
                    password,
                    "--unknown-suffix",
                    unknown,
                    "--json",
                ])
                .output()
                .unwrap(),
        );
        assert_eq!(info["pattern"], expected);
        assert_eq!(info["candidate_count"], count);
    }
}

#[test]
fn generated_bytes_are_reproducible_and_password_dependent() {
    let directory = tempfile::tempdir().unwrap();
    let mut captures = Vec::new();
    for (i, password) in ["ABCDEF12", "ABCDEF12", "ABCDEF13"].iter().enumerate() {
        let path = directory.path().join(format!("{i}.pcapng"));
        summary(
            generator()
                .arg("--output")
                .arg(&path)
                .args(["--password", password, "--json"])
                .output()
                .unwrap(),
        );
        captures.push(fs::read(path).unwrap());
    }
    assert_eq!(captures[0], captures[1]);
    assert_ne!(captures[0], captures[2]);
}

#[cfg(unix)]
#[test]
fn existing_output_symlinks_are_preserved() {
    let directory = tempfile::tempdir().unwrap();
    let target = directory.path().join("keep");
    let link = directory.path().join("fixture.pcapng");
    fs::write(&target, b"unchanged").unwrap();
    std::os::unix::fs::symlink(&target, &link).unwrap();
    assert!(
        !generator()
            .arg("--output")
            .arg(link)
            .args(["--password", "ABCDEF12"])
            .output()
            .unwrap()
            .status
            .success()
    );
    assert_eq!(fs::read(target).unwrap(), b"unchanged");
}
