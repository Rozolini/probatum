# Probatum

**Probatum** is a deterministic execution trace, AIR constraint system, and end-to-end **proof generation and verification** pipeline for a small toy VM. The wire format uses **`proof_version` v4**: Fiat–Shamir challenges, low-degree extension (LDE), Merkle commitments, and a **FRI** low-degree check. The repository is maintained as a **finished reference / portfolio** project (not a commercial product).

---

## Scope & limitations

- **Security & maturity** — This is a **toy / reference** stack for learning and portfolio use. It has **not** been independently audited and is **not** meant as production-grade cryptography or a general-purpose ZK platform for arbitrary real-world workloads.

- **What the CLI does today** — Commands like **`prove`** (and anything built on the same path) use a **fixed demo trace** defined in code, not a “upload your bytecode / program file” workflow. There is no supported CLI for arbitrary user programs without changing the source.

- **Where integration happens** — If you want to prove **your own** traces or VM semantics, the practical surface is the **Rust crates** (`probatum-prover`, `probatum-verifier`, `probatum-vm`, …): import them, build a trace in code, call `prove` / `verify`. The CLI is mainly a **reproducible demo** of the same pipeline.

- **What you get** — A **readable, runnable** end-to-end pipeline with tests and CI—not a hosted service, not a competitor to full proving stacks out of the box. Extending behavior means **forking or wiring new logic** in Rust.

---

## Architecture

### 1. Execution & constraint model (`probatum-vm`, `probatum-trace`, `probatum-air`, `probatum-field`, `probatum-arith`, `probatum-constraints`)

- **Deterministic VM execution** produces a fixed-length trace; the trace is hashed and bound into the proof context.
- **AIR validation** enforces opcode and register transitions; **arithmetization** maps the trace into field columns and selector semantics.
- **Constraint residuals** are evaluated on the trace domain and composed for the polynomial layer used by the prover.

### 2. Proof generation (`probatum-evaluation`, `probatum-transcript`, `probatum-fri`, `probatum-prover`)

- **LDE & commitments**: extend trace data and build Merkle roots over encoded leaves.
- **Fiat–Shamir transcript** (`probatum-transcript`, BLAKE3) derives challenges deterministically from the committed state.
- **FRI body** (`probatum-fri`): folding rounds and terminal check; the prover emits a serialized **`fri_body`** compatible with the standalone verifier.

### 3. Verification & tooling (`probatum-verifier`, `probatum-artifacts`, `probatum-cli`)

- **Verifier** recomputes the transcript, checks FRI and Merkle openings, and returns **structured failure codes** (e.g. version mismatch, tampered proof, FRI failure).
- **Artifacts & CLI**: prove/verify from disk, optional JSON reports, **`tamper-proof`** for tests, **`demo-attack`** (prove → tamper → verify status), **perf-smoke**, and **final-check** one-shot validation. See `cargo run -p probatum-cli -- --help` for all subcommands.

**Workspace crates:** `probatum-vm`, `probatum-trace`, `probatum-air`, `probatum-field`, `probatum-arith`, `probatum-constraints`, `probatum-evaluation`, `probatum-transcript`, `probatum-fri`, `probatum-prover`, `probatum-verifier`, `probatum-artifacts`, `probatum-cli`.

---

## Getting started

### Prerequisites

- **Rust** toolchain matching **`rust-toolchain.toml`** (MSRV **1.85**).
- **`Cargo.lock`** is committed; use `cargo` as usual on **Windows, Linux, or macOS** (no platform-specific native deps for the core library path).

### Quick start

1. **Clone the repository**

   ```bash
   git clone https://github.com/Rozolini/probatum.git
   cd probatum
   ```

2. **Build the workspace**

   ```bash
   cargo build --workspace
   ```

3. **Generate a proof and verify it**

   ```bash
   cargo run -p probatum-cli -- prove --out-dir artifacts/current
   cargo run -p probatum-cli -- verify --proof artifacts/current/proof.bin --report artifacts/current/verify_report.json
   ```

4. **One-shot validation** (prove, verify, receipt checks, perf smoke — as implemented by the CLI)

   ```bash
   cargo run -p probatum-cli -- final-check --out-dir artifacts/final-check
   ```

5. **Tamper demo** (writes a proof, tampers it, prints whether verification rejects it)

   ```bash
   cargo run -p probatum-cli -- demo-attack --out-dir artifacts/demo-attack
   ```

   List every subcommand: `cargo run -p probatum-cli -- --help`.

---

## Testing & verification

1. **Unit & integration tests** — full workspace:

   ```bash
   cargo test --workspace --all-targets
   ```

2. **Static checks** (what CI runs on every push/PR):

   ```bash
   cargo fmt --all --check
   cargo clippy --workspace --all-targets --all-features -- -D warnings
   ```

3. **Concurrency model tests (Loom)** — `probatum-vm` under the `loom` feature (see `.github/workflows/loom.yml`):

   ```bash
   cargo test -p probatum-vm --features loom
   ```

4. **Undefined-behavior exploration (Miri)** — scoped VM tests (see `.github/workflows/miri.yml`):

   ```bash
   cargo +nightly miri setup
   cargo +nightly miri test -p probatum-vm
   ```

5. **CI guardrails** — GitHub Actions also runs **tamper-guard** (prove → tamper → verify must fail), **perf-smoke**, **release-readiness** (build + prove/verify + tamper), and **final-check**.

6. **Optional** — Criterion benches: `cargo bench -p probatum-prover --bench integrated_prove`, `cargo bench -p probatum-verifier --bench verify_proof`. Fuzz targets live under `fuzz/` (**nightly** + [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz)).

---

## License

This project is licensed under the **MIT License** — see [`LICENSE`](LICENSE).
