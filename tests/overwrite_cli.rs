mod common;

use common::*;
use serde_json::{Value, json};
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn command() -> Command {
    Command::new(env!("CARGO_BIN_EXE_wifi-cap2hashcat"))
}
fn success(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
}
fn old_outputs(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
    let output = dir.join("capture.hc22000");
    let report = dir.join("capture.conversion.json");
    fs::write(&output, b"old hash\n").unwrap();
    fs::write(&report, b"old report\n").unwrap();
    (output, report)
}

#[test]
fn overwrite_replaces_single_hash_and_report_only_when_requested() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("capture.pcap");
    fs::write(&input, capture()).unwrap();
    let expected = command().arg(&input).output().unwrap().stdout;
    let (out, report) = old_outputs(dir.path());
    let mut args = command();
    args.arg(&input)
        .arg("-o")
        .arg(&out)
        .arg("--report")
        .arg(&report);
    let result = args.output().unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&result.stderr).contains("--overwrite"));
    assert_eq!(fs::read(&out).unwrap(), b"old hash\n");
    assert_eq!(fs::read(&report).unwrap(), b"old report\n");
    success(&args.arg("--overwrite").output().unwrap());
    assert_eq!(fs::read(&out).unwrap(), expected);
    let value: Value = serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
    assert_eq!(value["exports"].as_array().unwrap().len(), 1);
    assert_eq!(fs::read(&input).unwrap(), capture());
    assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 3); // no temp files remain
}

#[test]
fn overwrite_works_for_both_batch_forms_and_redirected_outputs() {
    for positional in [false, true] {
        for redirected in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            fs::write(dir.path().join("capture.pcap"), capture()).unwrap();
            fs::write(
                dir.path().join("capture.pcap.json"),
                b"{\"schema_version\":3}",
            )
            .unwrap();
            fs::write(
                dir.path().join("new.pcapng"),
                ng(&exchange(), E(false), 6, 0),
            )
            .unwrap();
            let target = if redirected {
                dir.path().join("results")
            } else {
                dir.path().to_path_buf()
            };
            fs::create_dir_all(&target).unwrap();
            let (out, report) = old_outputs(&target);
            let mut args = command();
            if !positional {
                args.arg("--directory");
            }
            args.arg(dir.path()).arg("--overwrite");
            if redirected {
                args.arg("--output-dir").arg(&target);
            }
            let result = args.output().unwrap();
            success(&result);
            assert!(result.stdout.is_empty());
            assert!(String::from_utf8_lossy(&result.stderr).contains("2 converted"));
            assert!(fs::read(&out).unwrap().starts_with(b"WPA*02*"));
            let value: Value = serde_json::from_slice(&fs::read(&report).unwrap()).unwrap();
            assert_eq!(value["capture_metadata"]["data"]["schema_version"], 3);
            assert!(target.join("new.hc22000").exists());
            assert!(target.join("new.conversion.json").exists());
            assert_eq!(
                fs::read(dir.path().join("capture.pcap.json")).unwrap(),
                b"{\"schema_version\":3}"
            );
            assert_eq!(
                fs::read(dir.path().join("capture.pcap")).unwrap(),
                capture()
            );
        }
    }
}

#[test]
fn overwrite_on_malformed_input_keeps_both_previous_results() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("capture.pcap"), b"not a capture").unwrap();
    fs::write(dir.path().join("good.pcap"), capture()).unwrap();
    let (out, report) = old_outputs(dir.path());
    let result = command()
        .arg("--directory")
        .arg(dir.path())
        .arg("--overwrite")
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(fs::read(out).unwrap(), b"old hash\n");
    assert_eq!(fs::read(report).unwrap(), b"old report\n");
    assert!(dir.path().join("good.hc22000").exists());
}

#[test]
fn no_pair_updates_report_and_explicitly_warns_that_previous_hash_is_unchanged() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("capture.pcap"),
        pcap(&[], 105, false, false),
    )
    .unwrap();
    let (out, report) = old_outputs(dir.path());
    let result = command()
        .arg("--directory")
        .arg(dir.path())
        .arg("--overwrite")
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&result.stderr).contains("previous hash file left unchanged"));
    assert_eq!(fs::read(out).unwrap(), b"old hash\n");
    let value: Value = serde_json::from_slice(&fs::read(report).unwrap()).unwrap();
    assert_eq!(value["exports"], json!([]));
}

#[test]
fn overwrite_never_replaces_input_through_output_or_report_arguments() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("capture.pcap");
    fs::write(&input, capture()).unwrap();
    fs::create_dir(dir.path().join("subdir")).unwrap();
    for alias in [input.clone(), dir.path().join("subdir/../capture.pcap")] {
        for flag in ["--output", "--report"] {
            let result = command()
                .arg(&input)
                .arg(flag)
                .arg(&alias)
                .arg("--overwrite")
                .output()
                .unwrap();
            assert_eq!(result.status.code(), Some(1));
            assert!(String::from_utf8_lossy(&result.stderr).contains("input capture or metadata"));
            assert_eq!(fs::read(&input).unwrap(), capture());
            assert!(result.stdout.is_empty());
        }
    }
}

#[test]
fn overwrite_protects_existing_single_file_sidecars() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("capture.pcap");
    fs::write(&input, capture()).unwrap();
    for name in ["capture.pcap.json", "capture.json"] {
        let metadata = dir.path().join(name);
        fs::write(&metadata, b"{\"original\":true}").unwrap();
        let result = command()
            .arg(&input)
            .arg("--report")
            .arg(&metadata)
            .arg("--overwrite")
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(1));
        assert_eq!(fs::read(metadata).unwrap(), b"{\"original\":true}");
    }
}

#[test]
fn batch_overwrite_protects_another_jobs_matching_sidecar() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["capture.pcap", "capture.conversion.pcap", "good.pcap"] {
        fs::write(dir.path().join(name), capture()).unwrap();
    }
    let metadata = dir.path().join("capture.conversion.json");
    fs::write(&metadata, b"{\"original\":true}").unwrap();
    let result = command()
        .arg("--directory")
        .arg(dir.path())
        .arg("--overwrite")
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(fs::read(metadata).unwrap(), b"{\"original\":true}");
    assert!(!dir.path().join("capture.hc22000").exists());
    assert!(dir.path().join("good.hc22000").exists());
    let report: Value = serde_json::from_slice(
        &fs::read(dir.path().join("capture.conversion.conversion.json")).unwrap(),
    )
    .unwrap();
    assert_eq!(report["capture_metadata"]["data"]["original"], true);
}

#[test]
fn overwrite_does_not_bypass_duplicate_batch_basenames() {
    let dir = tempfile::tempdir().unwrap();
    for name in ["capture.pcap", "capture.pcapng"] {
        fs::write(dir.path().join(name), capture()).unwrap();
    }
    let (out, report) = old_outputs(dir.path());
    let result = command()
        .arg("--directory")
        .arg(dir.path())
        .arg("--overwrite")
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(fs::read(out).unwrap(), b"old hash\n");
    assert_eq!(fs::read(report).unwrap(), b"old report\n");
}

#[test]
fn overwrite_rejects_colliding_output_report_and_directory_destinations() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("capture.pcap");
    fs::write(&input, capture()).unwrap();
    let (out, report) = old_outputs(dir.path());
    let result = command()
        .arg(&input)
        .arg("--output")
        .arg(&out)
        .arg("--report")
        .arg(&out)
        .arg("--overwrite")
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(fs::read(&out).unwrap(), b"old hash\n");
    fs::remove_file(&report).unwrap();
    fs::create_dir(&report).unwrap();
    let result = command()
        .arg(&input)
        .arg("--output")
        .arg(&out)
        .arg("--report")
        .arg(&report)
        .arg("--overwrite")
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(fs::read(&out).unwrap(), b"old hash\n");
    assert!(report.is_dir());
}

#[test]
fn replacing_an_output_hard_link_does_not_modify_the_original_capture() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("capture.pcap");
    let out = dir.path().join("hash.hc22000");
    fs::write(&input, capture()).unwrap();
    fs::hard_link(&input, &out).unwrap();
    success(
        &command()
            .arg(&input)
            .arg("--output")
            .arg(&out)
            .arg("--overwrite")
            .output()
            .unwrap(),
    );
    assert_eq!(fs::read(&input).unwrap(), capture());
    assert!(fs::read(out).unwrap().starts_with(b"WPA*02*"));
}

#[cfg(unix)]
#[test]
fn overwrite_rejects_symlink_outputs() {
    let dir = tempfile::tempdir().unwrap();
    let input = dir.path().join("capture.pcap");
    let out = dir.path().join("hash.hc22000");
    fs::write(&input, capture()).unwrap();
    std::os::unix::fs::symlink(&input, &out).unwrap();
    let result = command()
        .arg(&input)
        .arg("--output")
        .arg(&out)
        .arg("--overwrite")
        .output()
        .unwrap();
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(fs::read(input).unwrap(), capture());
    assert!(fs::symlink_metadata(out).unwrap().file_type().is_symlink());
}
