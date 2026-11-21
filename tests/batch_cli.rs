mod common;

use common::*;
use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_wifi-cap2hashcat"))
}

fn batch(path: &Path) -> Output {
    command().arg("--directory").arg(path).output().unwrap()
}

fn success(result: &Output) {
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert!(result.stdout.is_empty());
}

fn report(dir: &Path, stem: &str) -> Value {
    serde_json::from_slice(&fs::read(dir.join(format!("{stem}.conversion.json"))).unwrap()).unwrap()
}

#[test]
fn converts_all_captures_and_keeps_matching_metadata_as_context() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("first capture.pcap");
    fs::write(&input, capture()).unwrap();
    fs::write(dir.path().join("second.pcap"), capture()).unwrap();
    let metadata = json!({"schema_version": 3, "bssid": "02:00:00:00:00:01", "attempts": [{"id": 7}], "mic_verified": false});
    let bytes = serde_json::to_vec(&metadata).unwrap();
    let sidecar = dir.path().join("first capture.pcap.json");
    fs::write(&sidecar, &bytes).unwrap();
    let expected = command().arg(&input).output().unwrap().stdout;
    let result = batch(dir.path());
    success(&result);
    for stem in ["first capture", "second"] {
        assert_eq!(
            fs::read(dir.path().join(format!("{stem}.hc22000"))).unwrap(),
            expected
        );
        let r = report(dir.path(), stem);
        assert_eq!(r["validation"], "structural_only");
        assert_eq!(r["exports"].as_array().unwrap().len(), 1);
    }
    let r = report(dir.path(), "first capture");
    assert_eq!(r["capture_metadata"]["data"], metadata);
    assert!(
        r["capture_metadata"]["source"]
            .as_str()
            .unwrap()
            .ends_with("first capture.pcap.json")
    );
    assert!(
        report(dir.path(), "second")
            .get("capture_metadata")
            .is_none()
    );
    assert_eq!(fs::read(input).unwrap(), capture());
    assert_eq!(fs::read(sidecar).unwrap(), bytes);
    assert!(String::from_utf8_lossy(&result.stderr).contains("2 converted"));
}

#[test]
fn supports_pcapng_case_insensitive_extensions_and_basename_json() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("Wi-Fi.v2.PCAPNG"),
        ng(&exchange(), E(false), 6, 0),
    )
    .unwrap();
    fs::write(
        dir.path().join("Wi-Fi.v2.JSON"),
        b"\xef\xbb\xbf{\"schema_version\":1}",
    )
    .unwrap();
    success(&command().arg(dir.path()).output().unwrap());
    assert!(dir.path().join("Wi-Fi.v2.hc22000").is_file());
    assert_eq!(
        report(dir.path(), "Wi-Fi.v2")["capture_metadata"]["data"]["schema_version"],
        1
    );
}

#[test]
fn exact_capture_json_takes_precedence_over_basename_json() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.pcap"), capture()).unwrap();
    fs::write(
        dir.path().join("A.PCAP.JSON"),
        br#"{"source_kind":"recorder"}"#,
    )
    .unwrap();
    fs::write(dir.path().join("a.json"), b"not selected").unwrap();
    success(&batch(dir.path()));
    assert_eq!(
        report(dir.path(), "a")["capture_metadata"]["data"]["source_kind"],
        "recorder"
    );
}

#[test]
fn ignores_orphan_json_partial_captures_and_subdirectories() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("good.pcap"), capture()).unwrap();
    fs::write(dir.path().join("orphan.json"), b"invalid but unrelated").unwrap();
    fs::write(dir.path().join("unfinished.pcap.partial"), capture()).unwrap();
    fs::create_dir(dir.path().join("nested.pcap")).unwrap();
    fs::write(dir.path().join("nested.pcap/hidden.pcap"), capture()).unwrap();
    let result = batch(dir.path());
    success(&result);
    assert!(String::from_utf8_lossy(&result.stderr).contains("1 capture(s)"));
    assert!(!dir.path().join("orphan.hc22000").exists());
    assert!(!dir.path().join("unfinished.hc22000").exists());
    assert!(!dir.path().join("nested.pcap/hidden.hc22000").exists());
}

#[test]
fn empty_and_json_only_directories_exit_two() {
    let dir = tempfile::tempdir().unwrap();
    assert_eq!(batch(dir.path()).status.code(), Some(2));
    fs::write(dir.path().join("orphan.pcap.json"), b"{}").unwrap();
    let result = batch(dir.path());
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stderr).contains("No .pcap or .pcapng"));
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn output_collisions_fail_both_captures_before_publication_but_continue_others() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["same.pcap", "same.pcapng", "good.pcap"] {
        fs::write(dir.path().join(name), capture()).unwrap();
    }
    let result = batch(dir.path());
    assert_eq!(result.status.code(), Some(1));
    assert!(!dir.path().join("same.hc22000").exists());
    assert!(!dir.path().join("same.conversion.json").exists());
    assert!(dir.path().join("good.hc22000").is_file());
    assert!(String::from_utf8_lossy(&result.stderr).contains("2 failed"));
}

#[test]
fn protects_existing_outputs_reports_and_output_directories() {
    let dir = tempfile::tempdir().unwrap();
    for stem in [
        "existing_hash",
        "existing_report",
        "output_directory",
        "good",
    ] {
        fs::write(dir.path().join(format!("{stem}.pcap")), capture()).unwrap();
    }
    fs::write(dir.path().join("existing_hash.hc22000"), b"keep hash").unwrap();
    fs::write(
        dir.path().join("existing_report.conversion.json"),
        b"keep report",
    )
    .unwrap();
    fs::create_dir(dir.path().join("output_directory.hc22000")).unwrap();
    let result = batch(dir.path());
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(
        fs::read(dir.path().join("existing_hash.hc22000")).unwrap(),
        b"keep hash"
    );
    assert_eq!(
        fs::read(dir.path().join("existing_report.conversion.json")).unwrap(),
        b"keep report"
    );
    assert!(!dir.path().join("existing_hash.conversion.json").exists());
    assert!(!dir.path().join("existing_report.hc22000").exists());
    assert!(!dir.path().join("output_directory.conversion.json").exists());
    assert!(dir.path().join("good.hc22000").exists());
    assert!(String::from_utf8_lossy(&result.stderr).contains("3 failed"));
}

#[test]
fn rerun_never_changes_previous_outputs() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.pcap"), capture()).unwrap();
    success(&batch(dir.path()));
    let hash = fs::read(dir.path().join("a.hc22000")).unwrap();
    let report = fs::read(dir.path().join("a.conversion.json")).unwrap();
    fs::write(dir.path().join("new.pcap"), capture()).unwrap();
    let result = batch(dir.path());
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(fs::read(dir.path().join("a.hc22000")).unwrap(), hash);
    assert_eq!(
        fs::read(dir.path().join("a.conversion.json")).unwrap(),
        report
    );
    assert!(dir.path().join("new.hc22000").exists());
}

#[test]
fn malformed_captures_do_not_stop_other_jobs_and_errors_win_over_no_pair() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a_bad.pcap"), b"not a pcap").unwrap();
    fs::write(
        dir.path().join("b_empty.pcap"),
        pcap(&[], 105, false, false),
    )
    .unwrap();
    fs::write(dir.path().join("c_good.pcap"), capture()).unwrap();
    let result = batch(dir.path());
    assert_eq!(result.status.code(), Some(1));
    assert!(!dir.path().join("a_bad.hc22000").exists());
    assert!(!dir.path().join("a_bad.conversion.json").exists());
    assert!(!dir.path().join("b_empty.hc22000").exists());
    assert!(dir.path().join("b_empty.conversion.json").exists());
    assert!(dir.path().join("c_good.hc22000").exists());
    assert!(
        String::from_utf8_lossy(&result.stderr)
            .contains("1 converted; 1 without eligible pairs; 1 failed")
    );
}

#[test]
fn no_pair_writes_report_only_and_returns_partial_result_status() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("empty.pcap"),
        pcap(&[(0, beacon(SSID))], 105, false, false),
    )
    .unwrap();
    fs::write(dir.path().join("good.pcap"), capture()).unwrap();
    let result = batch(dir.path());
    assert_eq!(result.status.code(), Some(2));
    assert!(!dir.path().join("empty.hc22000").exists());
    assert_eq!(report(dir.path(), "empty")["exports"], json!([]));
    assert!(dir.path().join("good.hc22000").exists());
}

#[test]
fn optional_malformed_nonobject_and_oversized_metadata_warn_without_losing_hashes() {
    for bytes in [
        b"{".to_vec(),
        b"[]".to_vec(),
        vec![0xff],
        vec![b' '; 1024 * 1024 + 1],
    ] {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.pcap"), capture()).unwrap();
        fs::write(dir.path().join("a.pcap.json"), bytes).unwrap();
        let result = batch(dir.path());
        success(&result);
        let r = report(dir.path(), "a");
        assert!(r["capture_metadata"]["warning"].is_string());
        assert!(r["capture_metadata"].get("data").is_none());
        assert!(String::from_utf8_lossy(&result.stderr).contains("ignoring metadata"));
        assert!(dir.path().join("a.hc22000").exists());
    }
}

#[test]
fn metadata_does_not_supply_missing_ssid_or_claim_verified_hashes() {
    let dir = tempfile::tempdir().unwrap();
    let frames = vec![(1000, frame(1)), (2000, frame(2))];
    fs::write(dir.path().join("a.pcap"), pcap(&frames, 105, false, false)).unwrap();
    fs::write(
        dir.path().join("a.pcap.json"),
        br#"{"bssid":"02:00:00:00:00:01","ssid":"invented","mic_verified":true}"#,
    )
    .unwrap();
    assert_eq!(batch(dir.path()).status.code(), Some(2));
    let r = report(dir.path(), "a");
    assert_eq!(r["skipped_m2"]["missing_ssid"], 1);
    assert_eq!(r["validation"], "structural_only");
    assert_eq!(r["ssid_override_hex"], Value::Null);
    assert!(!dir.path().join("a.hc22000").exists());
}

#[test]
fn explicit_ap_and_ssid_options_apply_to_every_capture() {
    let dir = tempfile::tempdir().unwrap();
    let frames = vec![(1000, frame(1)), (2000, frame(2))];
    for name in ["one.pcap", "two.pcap"] {
        fs::write(dir.path().join(name), pcap(&frames, 105, false, false)).unwrap();
    }
    let result = command()
        .arg("--directory")
        .arg(dir.path())
        .args([
            "--bssid",
            "02:00:00:00:00:01",
            "--ssid",
            "test-lab",
            "--timeout-ms",
            "5000",
        ])
        .output()
        .unwrap();
    success(&result);
    for stem in ["one", "two"] {
        assert!(dir.path().join(format!("{stem}.hc22000")).exists());
        assert_eq!(
            report(dir.path(), stem)["ssid_override_hex"],
            hex::encode(SSID)
        );
    }
}

#[test]
fn validates_directory_arguments_without_creating_outputs() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("a.pcap");
    fs::write(&input, capture()).unwrap();
    for option in ["--output", "--report"] {
        let result = command()
            .arg("--directory")
            .arg(dir.path())
            .arg(option)
            .arg("unused")
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(2));
        let result = command()
            .arg(dir.path())
            .arg(option)
            .arg("unused")
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(1));
    }
    assert_eq!(
        command()
            .arg(&input)
            .arg("--directory")
            .arg(dir.path())
            .output()
            .unwrap()
            .status
            .code(),
        Some(2)
    );
    assert_eq!(batch(&input).status.code(), Some(1));
    assert_eq!(batch(&dir.path().join("missing")).status.code(), Some(1));
    assert_eq!(command().output().unwrap().status.code(), Some(2));
    assert_eq!(
        command()
            .arg("--directory")
            .arg(dir.path())
            .args(["--bssid", "02:00:00:00:00:01", "--ssid", ""])
            .output()
            .unwrap()
            .status
            .code(),
        Some(1)
    );
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[test]
fn metadata_directory_is_rejected_without_blocking_capture() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.pcap"), capture()).unwrap();
    fs::create_dir(dir.path().join("a.pcap.json")).unwrap();
    success(&batch(dir.path()));
    assert!(
        report(dir.path(), "a")["capture_metadata"]["warning"]
            .as_str()
            .unwrap()
            .contains("regular file")
    );
}

#[test]
fn output_dir_creates_nested_destination_and_preserves_sources() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("input captures");
    let output = dir.path().join("new directory/results");
    fs::create_dir(&input).unwrap();
    fs::write(input.join("first capture.pcap"), capture()).unwrap();
    let ng_bytes = ng(&exchange(), E(false), 6, 0);
    fs::write(input.join("second.PCAPNG"), &ng_bytes).unwrap();
    let metadata = br#"{"schema_version":3,"source_kind":"input folder"}"#;
    fs::write(input.join("first capture.pcap.json"), metadata).unwrap();
    let expected = command()
        .arg(input.join("first capture.pcap"))
        .output()
        .unwrap()
        .stdout;
    let result = command()
        .arg("--directory")
        .arg(&input)
        .arg("--output-dir")
        .arg(&output)
        .output()
        .unwrap();
    success(&result);
    assert_eq!(
        fs::read(output.join("first capture.hc22000")).unwrap(),
        expected
    );
    assert!(output.join("second.hc22000").is_file());
    assert_eq!(
        report(&output, "first capture")["capture_metadata"]["data"]["source_kind"],
        "input folder"
    );
    assert!(
        report(&output, "first capture")["source"]
            .as_str()
            .unwrap()
            .contains("input captures")
    );
    assert_eq!(fs::read_dir(&output).unwrap().count(), 4);
    assert_eq!(fs::read_dir(&input).unwrap().count(), 3);
    assert_eq!(
        fs::read(input.join("first capture.pcap")).unwrap(),
        capture()
    );
    assert_eq!(fs::read(input.join("second.PCAPNG")).unwrap(), ng_bytes);
    assert_eq!(
        fs::read(input.join("first capture.pcap.json")).unwrap(),
        metadata
    );
}

#[test]
fn output_dir_accepts_positional_input_and_relative_paths() {
    let dir = tempfile::tempdir().unwrap();
    fs::create_dir(dir.path().join("input")).unwrap();
    fs::write(dir.path().join("input/a.pcap"), capture()).unwrap();
    let result = command()
        .current_dir(dir.path())
        .args(["input", "--output-dir", "results/nested"])
        .output()
        .unwrap();
    success(&result);
    assert!(dir.path().join("results/nested/a.hc22000").is_file());
    assert!(
        dir.path()
            .join("results/nested/a.conversion.json")
            .is_file()
    );
    assert!(!dir.path().join("input/results").exists());
    assert!(!dir.path().join("input/a.hc22000").exists());
}

#[test]
fn output_dir_can_explicitly_be_the_input_directory() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a.pcap"), capture()).unwrap();
    success(
        &command()
            .arg("--directory")
            .arg(dir.path())
            .arg("--output-dir")
            .arg(dir.path())
            .output()
            .unwrap(),
    );
    assert!(dir.path().join("a.hc22000").is_file());
    assert!(dir.path().join("a.conversion.json").is_file());
}

#[test]
fn output_dir_preserves_existing_hashes_and_reports_and_continues() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("results");
    fs::create_dir(&output).unwrap();
    for stem in ["hash", "report", "good"] {
        fs::write(dir.path().join(format!("{stem}.pcap")), capture()).unwrap();
    }
    fs::write(output.join("hash.hc22000"), b"keep hash").unwrap();
    fs::write(output.join("report.conversion.json"), b"keep report").unwrap();
    let result = command()
        .arg("--directory")
        .arg(dir.path())
        .arg("--output-dir")
        .arg(&output)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(fs::read(output.join("hash.hc22000")).unwrap(), b"keep hash");
    assert_eq!(
        fs::read(output.join("report.conversion.json")).unwrap(),
        b"keep report"
    );
    assert!(!output.join("hash.conversion.json").exists());
    assert!(!output.join("report.hc22000").exists());
    assert!(output.join("good.hc22000").is_file());
    assert!(output.join("good.conversion.json").is_file());
    assert!(
        String::from_utf8_lossy(&result.stderr)
            .contains("1 converted; 0 without eligible pairs; 2 failed")
    );
    assert!(!dir.path().join("good.hc22000").exists());
}

#[test]
fn output_dir_preserves_collision_and_no_pair_behavior() {
    let dir = tempfile::tempdir().unwrap();
    let output = dir.path().join("results");
    for name in ["same.pcap", "same.pcapng"] {
        fs::write(dir.path().join(name), capture()).unwrap();
    }
    fs::write(dir.path().join("empty.pcap"), pcap(&[], 105, false, false)).unwrap();
    let result = command()
        .arg("--directory")
        .arg(dir.path())
        .arg("--output-dir")
        .arg(&output)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(fs::read_dir(&output).unwrap().count(), 1);
    assert_eq!(report(&output, "empty")["exports"], json!([]));
    assert!(!dir.path().join("empty.conversion.json").exists());
}

#[test]
fn output_dir_rejects_files_and_invalid_options_without_modifying_inputs() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("a.pcap");
    let output = dir.path().join("results");
    fs::write(&input, capture()).unwrap();
    let result = command()
        .arg("--directory")
        .arg(dir.path())
        .arg("--output-dir")
        .arg(&input)
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("Create output directory"));
    for flag in ["--output", "--report"] {
        assert_eq!(
            command()
                .arg("--directory")
                .arg(dir.path())
                .arg("--output-dir")
                .arg(&output)
                .args([flag, "unused"])
                .output()
                .unwrap()
                .status
                .code(),
            Some(2)
        );
    }
    assert_eq!(
        command()
            .arg(&input)
            .arg("--output-dir")
            .arg(&output)
            .output()
            .unwrap()
            .status
            .code(),
        Some(1)
    );
    assert_eq!(
        command()
            .arg("--directory")
            .arg(dir.path().join("missing"))
            .arg("--output-dir")
            .arg(&output)
            .output()
            .unwrap()
            .status
            .code(),
        Some(1)
    );
    assert_eq!(
        command()
            .arg("--directory")
            .arg(dir.path())
            .args(["--output-dir", ""])
            .output()
            .unwrap()
            .status
            .code(),
        Some(2)
    );
    assert!(!output.exists());
    assert_eq!(fs::read(input).unwrap(), capture());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
}

#[cfg(unix)]
#[test]
fn does_not_follow_symlink_captures_metadata_or_outputs() {
    use std::os::unix::fs::symlink;
    let dir = tempfile::tempdir().unwrap();
    let external = tempfile::tempdir().unwrap();
    let original = external.path().join("source.pcap");
    fs::write(&original, capture()).unwrap();
    symlink(&original, dir.path().join("linked.pcap")).unwrap();
    fs::write(dir.path().join("real.pcap"), capture()).unwrap();
    symlink(&original, dir.path().join("real.pcap.json")).unwrap();
    success(&batch(dir.path()));
    assert!(!dir.path().join("linked.hc22000").exists());
    assert!(report(dir.path(), "real")["capture_metadata"]["warning"].is_string());
    fs::write(dir.path().join("protected.pcap"), capture()).unwrap();
    symlink(&original, dir.path().join("protected.hc22000")).unwrap();
    assert_eq!(batch(dir.path()).status.code(), Some(1));
    assert_eq!(fs::read(original).unwrap(), capture());
}
