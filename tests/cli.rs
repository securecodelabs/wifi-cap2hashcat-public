mod common;
use common::*;
use std::fs;
use std::process::{Command, Output};
use tempfile::TempDir;

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_wifi-cap2hashcat"))
}
fn fixture() -> (TempDir, std::path::PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("capture with spaces.pca");
    fs::write(&path, capture()).unwrap();
    (dir, path)
}
fn success(result: &Output) {
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn stdout_contains_only_hash_lines() {
    let (_dir, input) = fixture();
    let result = command().arg(input).output().unwrap();
    success(&result);
    assert!(result.stdout.starts_with(b"WPA*02*"));
    assert_eq!(String::from_utf8_lossy(&result.stdout).lines().count(), 1);
    assert!(String::from_utf8_lossy(&result.stderr).contains("structural_only"));
}
#[test]
fn writes_new_hash_and_provenance_report_files() {
    let (dir, input) = fixture();
    let out = dir.path().join("output.hc22000");
    let report = dir.path().join("report.json");
    let result = command()
        .arg(input)
        .arg("-o")
        .arg(&out)
        .arg("--report")
        .arg(&report)
        .output()
        .unwrap();
    success(&result);
    assert!(result.stdout.is_empty());
    assert!(fs::read_to_string(out).unwrap().starts_with("WPA*02*"));
    let value: serde_json::Value = serde_json::from_slice(&fs::read(report).unwrap()).unwrap();
    assert_eq!(value["packets"], 5);
    assert_eq!(value["exports"][0]["m2_packet"], 3);
    assert_eq!(value["validation"], "structural_only");
}
#[test]
fn existing_output_is_preserved() {
    let (dir, input) = fixture();
    let out = dir.path().join("keep.hc22000");
    fs::write(&out, b"keep exactly").unwrap();
    let result = command().arg(input).arg("-o").arg(&out).output().unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(fs::read(out).unwrap(), b"keep exactly");
}
#[test]
fn existing_report_does_not_create_hash_output() {
    let (dir, input) = fixture();
    let out = dir.path().join("new.hc22000");
    let report = dir.path().join("keep.json");
    fs::write(&report, b"keep").unwrap();
    let result = command()
        .arg(input)
        .arg("-o")
        .arg(&out)
        .arg("--report")
        .arg(report)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(!out.exists());
}
#[test]
fn refuses_input_overwrite_and_colliding_output_paths() {
    let (dir, input) = fixture();
    let result = command()
        .arg(&input)
        .arg("-o")
        .arg(&input)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(fs::read(&input).unwrap(), capture());
    let out = dir.path().join("same.txt");
    let result = command()
        .arg(input)
        .arg("-o")
        .arg(&out)
        .arg("--report")
        .arg(&out)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(!out.exists());
}
#[test]
fn no_handshake_exits_two_and_writes_only_report() {
    let (dir, input) = fixture();
    fs::write(&input, pcap(&[(0, beacon(SSID))], 105, false, false)).unwrap();
    let out = dir.path().join("empty.hc22000");
    let report = dir.path().join("report.json");
    let result = command()
        .arg(input)
        .arg("-o")
        .arg(&out)
        .arg("--report")
        .arg(&report)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(!out.exists());
    assert!(report.exists());
    assert!(result.stdout.is_empty());
}
#[test]
fn malformed_capture_does_not_publish_partial_hashes_or_report() {
    let (dir, input) = fixture();
    let mut b = capture();
    b.push(0);
    fs::write(&input, b).unwrap();
    let out = dir.path().join("out.hc22000");
    let report = dir.path().join("report.json");
    let result = command()
        .arg(input)
        .arg("-o")
        .arg(&out)
        .arg("--report")
        .arg(&report)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(!out.exists() && !report.exists());
}
#[test]
fn validates_mac_ssid_and_timeout_arguments() {
    let (_dir, input) = fixture();
    for args in [
        vec!["--bssid", "02:::00"],
        vec!["--bssid", "ff:ff:ff:ff:ff:ff"],
        vec!["--ssid", "test"],
        vec!["--timeout-ms", "0"],
        vec!["--timeout-ms", "60001"],
    ] {
        let result = command().arg(&input).args(args).output().unwrap();
        assert_eq!(result.status.code(), Some(2));
    }
    let result = command()
        .arg(input)
        .args(["--bssid", "02:00:00:00:00:01", "--ssid-hex", "gg"])
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
}
#[test]
fn nonexistent_destination_parent_fails_clearly() {
    let (dir, input) = fixture();
    let out = dir.path().join("missing").join("out.hc22000");
    let result = command().arg(input).arg("-o").arg(out).output().unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("directory does not exist"));
}

#[cfg(unix)]
#[test]
fn named_pipe_input_is_rejected_without_waiting_for_a_writer() {
    use std::time::{Duration, Instant};
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("input.pcap");
    assert!(
        Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let mut child = command()
        .arg(&fifo)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        if child.try_wait().unwrap().is_some() {
            let output = child.wait_with_output().unwrap();
            assert_eq!(output.status.code(), Some(1));
            assert!(String::from_utf8_lossy(&output.stderr).contains("regular file"));
            break;
        }
        if Instant::now() >= deadline {
            child.kill().unwrap();
            child.wait().unwrap();
            panic!("Opening a named pipe blocked the converter");
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}
