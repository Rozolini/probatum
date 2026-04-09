//! End-to-end CLI tests for artifact contracts and failure behavior.

use probatum_air::{AirDiagnostics, AirStatus};
use probatum_artifacts::{PROOF_VERSION, VM_VERSION, decode_receipt, encode_receipt};
use probatum_prover::{PROOF_VERSION as PROVER_PROOF_VERSION, decode_proof};
use serde_json::Value;
use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_temp_dir(prefix: &str) -> PathBuf {
    let ts =
        SystemTime::now().duration_since(UNIX_EPOCH).expect("clock should be valid").as_nanos();
    let dir = std::env::temp_dir().join(format!("{prefix}_{ts}"));
    fs::create_dir_all(&dir).expect("temp dir should be created");
    dir
}

fn cli_bin() -> &'static str {
    env!("CARGO_BIN_EXE_probatum-cli")
}

#[test]
fn prove_writes_expected_artifacts_and_verify_passes() {
    let out_dir = unique_temp_dir("probatum_e2e_happy");
    let proof_path = out_dir.join("proof.bin");
    let receipt_path = out_dir.join("receipt.json");
    let air_diag_path = out_dir.join("air_diagnostics.json");
    let verify_report_path = out_dir.join("verify_report.json");

    let prove_status = Command::new(cli_bin())
        .arg("prove")
        .arg("--out-dir")
        .arg(&out_dir)
        .status()
        .expect("prove command should run");
    assert!(prove_status.success());

    assert!(proof_path.exists(), "proof artifact must exist");
    assert!(receipt_path.exists(), "receipt artifact must exist");
    assert!(air_diag_path.exists(), "air diagnostics artifact must exist");

    let proof_raw = fs::read(&proof_path).expect("proof should be readable");
    let proof = decode_proof(&proof_raw).expect("proof should decode");
    let receipt_raw = fs::read(&receipt_path).expect("receipt should be readable");
    let receipt = decode_receipt(&receipt_raw).expect("receipt should decode");
    let diag_raw = fs::read(&air_diag_path).expect("air diagnostics should be readable");
    let diag: AirDiagnostics =
        serde_json::from_slice(&diag_raw).expect("air diagnostics should decode");

    assert_eq!(receipt.proof_version, PROOF_VERSION);
    assert_eq!(proof.proof_version, PROVER_PROOF_VERSION);
    assert_eq!(receipt.vm_version, VM_VERSION);
    assert_eq!(receipt.trace_len, proof.trace_len);
    assert_eq!(receipt.trace_digest, proof.trace_digest);
    assert_eq!(receipt.air_reason_code, "ok");
    assert_eq!(diag.status, AirStatus::Ok);

    let verify_status = Command::new(cli_bin())
        .arg("verify")
        .arg("--proof")
        .arg(&proof_path)
        .arg("--report")
        .arg(&verify_report_path)
        .status()
        .expect("verify command should run");
    assert!(verify_status.success());

    let verify_report_raw =
        fs::read(&verify_report_path).expect("verify report should be readable");
    let verify_report: Value =
        serde_json::from_slice(&verify_report_raw).expect("verify report should decode");
    assert_eq!(verify_report["status"], "ok");
    assert!(verify_report["failure_code"].is_null());
}

#[test]
fn tampered_proof_is_rejected() {
    let out_dir = unique_temp_dir("probatum_e2e_tamper");
    let proof_path = out_dir.join("proof.bin");
    let tampered_path = out_dir.join("proof_tampered.bin");
    let verify_report_path = out_dir.join("verify_report_tampered.json");

    let prove_status = Command::new(cli_bin())
        .arg("prove")
        .arg("--out-dir")
        .arg(&out_dir)
        .status()
        .expect("prove command should run");
    assert!(prove_status.success());

    let tamper_status = Command::new(cli_bin())
        .arg("tamper-proof")
        .arg("--input")
        .arg(&proof_path)
        .arg("--output")
        .arg(&tampered_path)
        .status()
        .expect("tamper-proof command should run");
    assert!(tamper_status.success());

    let verify_tampered_status = Command::new(cli_bin())
        .arg("verify")
        .arg("--proof")
        .arg(&tampered_path)
        .arg("--report")
        .arg(&verify_report_path)
        .status()
        .expect("verify tampered command should run");
    assert!(!verify_tampered_status.success(), "tampered proof must fail verification");

    let verify_report_raw =
        fs::read(&verify_report_path).expect("verify report should be readable");
    let verify_report: Value =
        serde_json::from_slice(&verify_report_raw).expect("verify report should decode");
    assert_eq!(verify_report["status"], "fail");
    assert_eq!(verify_report["failure_code"]["domain"], "verifier");
    let code = verify_report["failure_code"]["code"].as_str().expect("failure code string");
    assert!(
        matches!(
            code,
            "transcript_mismatch"
                | "fri_low_degree_check_failed"
                | "fri_payload_invalid"
                | "fri_betas_mismatch"
        ),
        "unexpected failure code: {code}"
    );
}

#[test]
fn receipt_version_mismatch_is_rejected() {
    let out_dir = unique_temp_dir("probatum_e2e_receipt_version");
    let proof_path = out_dir.join("proof.bin");
    let receipt_path = out_dir.join("receipt.json");

    let prove_status = Command::new(cli_bin())
        .arg("prove")
        .arg("--out-dir")
        .arg(&out_dir)
        .status()
        .expect("prove command should run");
    assert!(prove_status.success());

    let receipt_raw = fs::read(&receipt_path).expect("receipt should be readable");
    let mut receipt = decode_receipt(&receipt_raw).expect("receipt should decode");
    receipt.artifact_version = "v999".to_string();
    fs::write(&receipt_path, encode_receipt(&receipt).expect("receipt should encode"))
        .expect("mutated receipt should write");

    let verify_status = Command::new(cli_bin())
        .arg("verify")
        .arg("--proof")
        .arg(&proof_path)
        .status()
        .expect("verify command should run");
    assert!(!verify_status.success(), "receipt version mismatch must fail verification");
}

#[test]
fn deterministic_prove_outputs_are_stable() {
    let out_dir_a = unique_temp_dir("probatum_e2e_det_a");
    let out_dir_b = unique_temp_dir("probatum_e2e_det_b");

    let status_a = Command::new(cli_bin())
        .arg("prove")
        .arg("--out-dir")
        .arg(&out_dir_a)
        .status()
        .expect("prove A should run");
    assert!(status_a.success());

    let status_b = Command::new(cli_bin())
        .arg("prove")
        .arg("--out-dir")
        .arg(&out_dir_b)
        .status()
        .expect("prove B should run");
    assert!(status_b.success());

    let proof_a = fs::read(out_dir_a.join("proof.bin")).expect("proof A should exist");
    let proof_b = fs::read(out_dir_b.join("proof.bin")).expect("proof B should exist");
    let receipt_a = fs::read(out_dir_a.join("receipt.json")).expect("receipt A should exist");
    let receipt_b = fs::read(out_dir_b.join("receipt.json")).expect("receipt B should exist");
    let output_a =
        fs::read(out_dir_a.join("public_output.json")).expect("public output A should exist");
    let output_b =
        fs::read(out_dir_b.join("public_output.json")).expect("public output B should exist");

    assert_eq!(proof_a, proof_b, "proof bytes must be deterministic");
    assert_eq!(receipt_a, receipt_b, "receipt bytes must be deterministic");
    assert_eq!(output_a, output_b, "public output must be deterministic");
}
