//! CLI orchestration layer for proving, verification, tamper demos, and reports.

use anyhow::{Result, anyhow};
use clap::{Parser, Subcommand};
use probatum_air::{AirConfig, diagnostics as air_diagnostics};
use probatum_artifacts::{
    ARTIFACT_VERSION, Receipt, VM_VERSION, decode_receipt, encode_public_output, encode_receipt,
};
use probatum_prover::{decode_proof, encode_proof, prove};
use probatum_trace::{ExecutionTrace, TraceRow};
use probatum_verifier::{VerifyFailureCode, VerifyOutcome, verify_detailed};
use probatum_vm::{Instruction, OpCode, VmState, step};
use serde::Serialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Instant;
use thiserror::Error;

#[derive(Parser, Debug)]
#[command(name = "probatum")]
#[command(about = "Probatum STARK engine scaffold")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand, Debug)]
enum Command {
    Prove {
        #[arg(long, default_value = "artifacts/current")]
        out_dir: PathBuf,
    },
    Verify {
        #[arg(long, default_value = "artifacts/current/proof.bin")]
        proof: PathBuf,
        #[arg(long)]
        report: Option<PathBuf>,
    },
    TamperProof {
        #[arg(long, default_value = "artifacts/current/proof.bin")]
        input: PathBuf,
        #[arg(long, default_value = "artifacts/current/proof_tampered.bin")]
        output: PathBuf,
    },
    DemoAttack {
        #[arg(long, default_value = "artifacts/current")]
        out_dir: PathBuf,
    },
    PerfSmoke {
        #[arg(long, default_value_t = 50)]
        iterations: usize,
        #[arg(long, default_value = "artifacts/current/perf_report.json")]
        out: PathBuf,
        #[arg(long)]
        max_p50_us: Option<u128>,
        #[arg(long)]
        max_p95_us: Option<u128>,
    },
    FinalCheck {
        #[arg(long, default_value = "artifacts/final-check")]
        out_dir: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Prove { out_dir } => {
            let trace = sample_trace()?;
            let proof = prove(&trace)?;
            write_artifacts(&out_dir, &trace, &proof, trace.rows.last().map_or(0, |row| row.acc))?;
            println!(
                "PROOF_GENERATED trace_len={} transcript={} artifacts_path={}",
                proof.trace_len,
                proof.transcript,
                out_dir.display()
            );
        }
        Command::Verify { proof, report } => {
            let proof_path = proof;
            let proof_bytes = fs::read(&proof_path)?;
            let decoded_proof = decode_proof(&proof_bytes)?;
            if let Some(receipt) = read_neighbor_receipt(&proof_path)? {
                if let Err(code) = ensure_receipt_matches_proof(&receipt, &decoded_proof) {
                    maybe_write_verify_report(
                        &report,
                        &proof_path,
                        VerifyReportStatus::Fail,
                        Some(VerifyReportFailureCode::Receipt(code)),
                    )?;
                    return Err(anyhow!("receipt verification failed: {:?}", code));
                }
            }
            match verify_detailed(&decoded_proof) {
                VerifyOutcome::Ok => {
                    maybe_write_verify_report(&report, &proof_path, VerifyReportStatus::Ok, None)?;
                    println!("VERIFY_OK");
                }
                VerifyOutcome::Fail(code) => {
                    maybe_write_verify_report(
                        &report,
                        &proof_path,
                        VerifyReportStatus::Fail,
                        Some(VerifyReportFailureCode::Verifier(code)),
                    )?;
                    return Err(anyhow!("proof verification failed: {:?}", code));
                }
            }
        }
        Command::TamperProof { input, output } => {
            tamper_proof_file(&input, &output)?;
            println!("TAMPERED_PROOF_WRITTEN path={}", output.display());
        }
        Command::DemoAttack { out_dir } => {
            let proof_path = out_dir.join("proof.bin");
            let tampered_path = out_dir.join("proof_tampered.bin");
            let trace = sample_trace()?;
            let proof = prove(&trace)?;
            write_artifacts(&out_dir, &trace, &proof, trace.rows.last().map_or(0, |row| row.acc))?;
            tamper_proof_file(&proof_path, &tampered_path)?;

            let tampered = fs::read(&tampered_path)?;
            let status = match decode_proof(&tampered) {
                Ok(decoded) => match verify_detailed(&decoded) {
                    VerifyOutcome::Ok => "UNEXPECTED_VERIFY_OK",
                    VerifyOutcome::Fail(_) => "TAMPER_DETECTED_VERIFY_FAIL",
                },
                Err(_) => "TAMPER_DETECTED_DECODE_FAIL",
            };
            println!("DEMO_ATTACK_RESULT status={} path={}", status, tampered_path.display());
            if status == "UNEXPECTED_VERIFY_OK" {
                return Err(anyhow!("tampered proof unexpectedly verified"));
            }
        }
        Command::PerfSmoke { iterations, out, max_p50_us, max_p95_us } => {
            let report = run_perf_smoke(iterations)?;
            enforce_perf_thresholds(&report, max_p50_us, max_p95_us)?;
            if let Some(parent) = out.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&out, serde_json::to_vec_pretty(&report)?)?;
            println!(
                "PERF_SMOKE_OK iterations={} p50_us={} p95_us={} out={}",
                report.iterations,
                report.p50_us,
                report.p95_us,
                out.display()
            );
        }
        Command::FinalCheck { out_dir } => {
            let report = run_final_check(&out_dir)?;
            let report_path = out_dir.join("final_check_report.json");
            fs::write(&report_path, serde_json::to_vec_pretty(&report)?)?;
            println!(
                "FINAL_CHECK_OK prove_verify={} tamper_rejected={} perf_smoke={} report={}",
                report.prove_verify_ok,
                report.tamper_rejected,
                report.perf_smoke_ok,
                report_path.display()
            );
        }
    }
    Ok(())
}

/// Writes all primary artifacts produced by the `prove` flow.
fn write_artifacts(
    out_dir: &Path,
    trace: &ExecutionTrace,
    proof: &probatum_prover::Proof,
    accumulator: u64,
) -> Result<()> {
    fs::create_dir_all(out_dir)?;
    let proof_path = out_dir.join("proof.bin");
    let output_path = out_dir.join("public_output.json");
    let receipt_path = out_dir.join("receipt.json");
    let air_diag_path = out_dir.join("air_diagnostics.json");
    let diag = air_diagnostics(trace, AirConfig::default());

    fs::write(&proof_path, encode_proof(proof)?)?;
    let public_output = probatum_artifacts::PublicOutput { accumulator };
    fs::write(&output_path, encode_public_output(&public_output)?)?;
    let receipt = Receipt::new(
        proof.transcript.clone(),
        proof.trace_len,
        proof.trace_digest.clone(),
        diag.reason_code.clone(),
    );
    fs::write(&receipt_path, encode_receipt(&receipt)?)?;
    fs::write(&air_diag_path, serde_json::to_vec_pretty(&diag)?)?;
    Ok(())
}

/// Reads `receipt.json` from the same directory as the proof when present.
fn read_neighbor_receipt(proof_path: &Path) -> Result<Option<Receipt>> {
    let Some(parent) = proof_path.parent() else {
        return Ok(None);
    };
    let receipt_path = parent.join("receipt.json");
    if !receipt_path.exists() {
        return Ok(None);
    }
    let raw = fs::read(receipt_path)?;
    let receipt = decode_receipt(&raw)?;
    Ok(Some(receipt))
}

/// Enforces strict receipt-to-proof consistency before proof verification.
fn ensure_receipt_matches_proof(
    receipt: &Receipt,
    proof: &probatum_prover::Proof,
) -> Result<(), ReceiptCheckFailureCode> {
    if receipt.artifact_version != ARTIFACT_VERSION {
        return Err(ReceiptCheckFailureCode::ArtifactVersionMismatch);
    }
    if receipt.vm_version != VM_VERSION {
        return Err(ReceiptCheckFailureCode::VmVersionMismatch);
    }
    if receipt.proof_version != proof.proof_version {
        return Err(ReceiptCheckFailureCode::ProofVersionMismatch);
    }
    if receipt.air_reason_code != "ok" {
        return Err(ReceiptCheckFailureCode::AirReasonCodeNotOk);
    }
    if receipt.transcript != proof.transcript {
        return Err(ReceiptCheckFailureCode::TranscriptMismatch);
    }
    if receipt.trace_len != proof.trace_len {
        return Err(ReceiptCheckFailureCode::TraceLenMismatch);
    }
    if receipt.trace_digest != proof.trace_digest {
        return Err(ReceiptCheckFailureCode::TraceDigestMismatch);
    }
    Ok(())
}

/// Produces a minimally modified proof file for tamper-detection tests.
fn tamper_proof_file(input: &Path, output: &Path) -> Result<()> {
    let mut bytes = fs::read(input)?;
    if bytes.is_empty() {
        return Err(anyhow!("proof input is empty"));
    }
    let idx = bytes.len() / 2;
    bytes[idx] ^= 0x01;
    fs::write(output, bytes)?;
    Ok(())
}

/// Builds the canonical sample execution trace used by demos and smoke checks.
fn sample_trace() -> Result<ExecutionTrace> {
    let program = [
        Instruction { op: OpCode::Add, arg: 2 },
        Instruction { op: OpCode::Mul, arg: 4 },
        Instruction { op: OpCode::Add, arg: 0 },
        Instruction { op: OpCode::Halt, arg: 0 },
    ];
    let mut state = VmState::default();
    let mut trace = ExecutionTrace::default();

    while !state.halted {
        let instruction =
            program.get(state.pc).ok_or_else(|| anyhow!("pc out of range during trace build"))?;
        let op_tag = match instruction.op {
            OpCode::Add => 1,
            OpCode::Mul => 2,
            OpCode::Halt => 3,
        };
        trace.rows.push(TraceRow {
            clk: trace.rows.len() as u64,
            pc: state.pc as u64,
            acc: state.acc,
            op_tag,
            op_arg: instruction.arg,
        });
        step(&mut state, &program)?;
    }

    Ok(trace)
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct PerfReport {
    iterations: usize,
    min_us: u128,
    p50_us: u128,
    p95_us: u128,
    max_us: u128,
}

fn run_perf_smoke(iterations: usize) -> Result<PerfReport> {
    if iterations == 0 {
        return Err(anyhow!("iterations must be greater than zero"));
    }
    let trace = sample_trace()?;
    let mut samples_us = Vec::with_capacity(iterations);
    for _ in 0..iterations {
        let started = Instant::now();
        let _proof = prove(&trace)?;
        samples_us.push(started.elapsed().as_micros());
    }
    samples_us.sort_unstable();
    let min_us = samples_us[0];
    let max_us = samples_us[samples_us.len() - 1];
    let p50_us = percentile(&samples_us, 50);
    let p95_us = percentile(&samples_us, 95);
    Ok(PerfReport { iterations, min_us, p50_us, p95_us, max_us })
}

fn percentile(sorted_us: &[u128], p: usize) -> u128 {
    let last_idx = sorted_us.len() - 1;
    let idx = (last_idx * p) / 100;
    sorted_us[idx]
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct FinalCheckReport {
    prove_verify_ok: bool,
    tamper_rejected: bool,
    perf_smoke_ok: bool,
    verify_failure_code: Option<VerifyReportFailureCode>,
}

fn run_final_check(out_dir: &Path) -> Result<FinalCheckReport> {
    fs::create_dir_all(out_dir)?;
    let trace = sample_trace()?;
    let proof = prove(&trace)?;
    write_artifacts(out_dir, &trace, &proof, trace.rows.last().map_or(0, |row| row.acc))?;

    let verify_outcome = verify_detailed(&proof);
    let prove_verify_ok = matches!(verify_outcome, VerifyOutcome::Ok);

    let proof_path = out_dir.join("proof.bin");
    let tampered_path = out_dir.join("proof_tampered.bin");
    tamper_proof_file(&proof_path, &tampered_path)?;
    let tampered_bytes = fs::read(&tampered_path)?;
    let tamper_rejected = match decode_proof(&tampered_bytes) {
        Ok(decoded) => matches!(verify_detailed(&decoded), VerifyOutcome::Fail(_)),
        Err(_) => true,
    };

    let perf_report = run_perf_smoke(20)?;
    let perf_smoke_ok = enforce_perf_thresholds(&perf_report, Some(2_000), Some(10_000)).is_ok();

    let verify_failure_code = match verify_outcome {
        VerifyOutcome::Ok => None,
        VerifyOutcome::Fail(code) => Some(VerifyReportFailureCode::Verifier(code)),
    };

    Ok(FinalCheckReport { prove_verify_ok, tamper_rejected, perf_smoke_ok, verify_failure_code })
}

fn enforce_perf_thresholds(
    report: &PerfReport,
    max_p50_us: Option<u128>,
    max_p95_us: Option<u128>,
) -> Result<()> {
    if let Some(max_p50) = max_p50_us {
        if report.p50_us > max_p50 {
            return Err(anyhow!(
                "perf threshold exceeded: p50_us={} > max_p50_us={}",
                report.p50_us,
                max_p50
            ));
        }
    }
    if let Some(max_p95) = max_p95_us {
        if report.p95_us > max_p95 {
            return Err(anyhow!(
                "perf threshold exceeded: p95_us={} > max_p95_us={}",
                report.p95_us,
                max_p95
            ));
        }
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
enum VerifyReportStatus {
    Ok,
    Fail,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Error)]
#[serde(rename_all = "snake_case")]
pub enum ReceiptCheckFailureCode {
    #[error("artifact_version_mismatch")]
    ArtifactVersionMismatch,
    #[error("vm_version_mismatch")]
    VmVersionMismatch,
    #[error("proof_version_mismatch")]
    ProofVersionMismatch,
    #[error("air_reason_code_not_ok")]
    AirReasonCodeNotOk,
    #[error("transcript_mismatch")]
    TranscriptMismatch,
    #[error("trace_len_mismatch")]
    TraceLenMismatch,
    #[error("trace_digest_mismatch")]
    TraceDigestMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "domain", content = "code", rename_all = "snake_case")]
enum VerifyReportFailureCode {
    Verifier(VerifyFailureCode),
    Receipt(ReceiptCheckFailureCode),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
struct VerifyReport {
    status: VerifyReportStatus,
    failure_code: Option<VerifyReportFailureCode>,
    proof_path: String,
}

fn maybe_write_verify_report(
    report_path: &Option<PathBuf>,
    proof_path: &Path,
    status: VerifyReportStatus,
    failure_code: Option<VerifyReportFailureCode>,
) -> Result<()> {
    let Some(path) = report_path else {
        return Ok(());
    };
    let report =
        VerifyReport { status, failure_code, proof_path: proof_path.display().to_string() };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(path, serde_json::to_vec_pretty(&report)?)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use probatum_trace::{ExecutionTrace, TraceRow};

    fn four_row_trace() -> ExecutionTrace {
        ExecutionTrace {
            rows: vec![
                TraceRow { clk: 0, pc: 0, acc: 0, op_tag: 1, op_arg: 2 },
                TraceRow { clk: 1, pc: 1, acc: 2, op_tag: 2, op_arg: 4 },
                TraceRow { clk: 2, pc: 2, acc: 8, op_tag: 1, op_arg: 0 },
                TraceRow { clk: 3, pc: 3, acc: 8, op_tag: 3, op_arg: 0 },
            ],
        }
    }

    #[test]
    fn receipt_mismatch_is_rejected() {
        let trace = four_row_trace();
        let bad_proof = prove(&trace).expect("proof");
        let receipt = Receipt::new(
            "wrong-transcript".to_string(),
            bad_proof.trace_len,
            bad_proof.trace_digest.clone(),
            "ok".to_string(),
        );
        let err = ensure_receipt_matches_proof(&receipt, &bad_proof)
            .expect_err("mismatch should fail verification");
        assert_eq!(err, ReceiptCheckFailureCode::TranscriptMismatch);
    }

    #[test]
    fn tampered_proof_fails_to_decode_or_verify() {
        let temp_dir = std::env::temp_dir().join("probatum_cli_tamper_test");
        let _ = fs::create_dir_all(&temp_dir);
        let input = temp_dir.join("proof.bin");
        let output = temp_dir.join("proof_tampered.bin");

        let trace = sample_trace().expect("trace should build");
        let proof = prove(&trace).expect("proof should build");
        fs::write(&input, encode_proof(&proof).expect("proof should encode"))
            .expect("proof should write");
        tamper_proof_file(&input, &output).expect("tamper should pass");

        let tampered = fs::read(&output).expect("tampered proof should exist");
        let decoded = decode_proof(&tampered);
        if let Ok(decoded_proof) = decoded {
            assert!(matches!(verify_detailed(&decoded_proof), VerifyOutcome::Fail(_)));
        } else {
            assert!(decoded.is_err());
        }
    }

    #[test]
    fn receipt_version_mismatch_is_rejected() {
        let proof = prove(&four_row_trace()).expect("proof");
        let mut receipt = Receipt::new(
            proof.transcript.clone(),
            proof.trace_len,
            proof.trace_digest.clone(),
            "ok".to_string(),
        );
        receipt.artifact_version = "v999".to_string();
        let err = ensure_receipt_matches_proof(&receipt, &proof)
            .expect_err("artifact version mismatch should fail");
        assert_eq!(err, ReceiptCheckFailureCode::ArtifactVersionMismatch);
    }

    #[test]
    fn writes_verify_report_when_path_provided() {
        let dir = std::env::temp_dir().join("probatum_verify_report_test");
        let _ = fs::create_dir_all(&dir);
        let report_path = dir.join("verify_report.json");
        maybe_write_verify_report(
            &Some(report_path.clone()),
            Path::new("proof.bin"),
            VerifyReportStatus::Fail,
            Some(VerifyReportFailureCode::Verifier(VerifyFailureCode::TranscriptMismatch)),
        )
        .expect("report write should succeed");
        let raw = fs::read(&report_path).expect("report should exist");
        let text = String::from_utf8(raw).expect("report must be utf8");
        assert!(text.contains("transcript_mismatch"));
    }

    #[test]
    fn perf_smoke_produces_valid_report() {
        let report = run_perf_smoke(5).expect("perf smoke should pass");
        assert_eq!(report.iterations, 5);
        assert!(report.min_us <= report.p50_us);
        assert!(report.p50_us <= report.p95_us);
        assert!(report.p95_us <= report.max_us);
    }

    #[test]
    fn perf_thresholds_fail_when_exceeded() {
        let report = PerfReport { iterations: 10, min_us: 1, p50_us: 10, p95_us: 20, max_us: 30 };
        let err =
            enforce_perf_thresholds(&report, Some(5), None).expect_err("p50 threshold should fail");
        assert!(err.to_string().contains("p50_us"));
    }

    #[test]
    fn final_check_report_is_successful() {
        let dir = std::env::temp_dir().join("probatum_final_check_test");
        let _ = fs::create_dir_all(&dir);
        let report = run_final_check(&dir).expect("final check should pass");
        assert!(report.prove_verify_ok);
        assert!(report.tamper_rejected);
        assert!(report.perf_smoke_ok);
    }
}
