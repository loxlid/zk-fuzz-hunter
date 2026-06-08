//! ZK-FUZZ-HUNTER — an under-constrained-signal fuzzing harness for R1CS.
//!
//! Pipeline:
//!   1. Load config (fuzzing budget, RNG seed, field choice).
//!   2. Build two sample constraint systems — one properly constrained, one
//!      with the classic `x*x = y` under-constraint.
//!   3. Run the fuzzer on each, holding public inputs fixed while searching
//!      the private witness space for a *second* satisfying assignment.
//!   4. Print a clear verdict per system.
//!
//! ⚠️ DEMO / EDUCATIONAL. This is a *simplified* model of R1CS over a small
//! u128-safe prime field — it illustrates the under-constrained bug class, it
//! is **not** a production circom/snark analyzer. See the README.

mod config;
mod field;
mod fuzzer;
mod r1cs;

use anyhow::Result;
use tracing_subscriber::{fmt, EnvFilter};

use crate::config::FuzzConfig;
use crate::field::F;
use crate::fuzzer::{hunt, Report};
use crate::r1cs::{
    under_constrained, under_constrained_witness, well_constrained, well_constrained_witness,
    ConstraintSystem,
};

fn main() -> Result<()> {
    fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")))
        .init();

    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_string());

    // The config file is optional for the demo: fall back to defaults so the
    // tool runs out-of-the-box with `cargo run`.
    let cfg = match FuzzConfig::load(&config_path) {
        Ok(c) => c,
        Err(_) => {
            tracing::info!(
                "no config at {config_path} — using built-in defaults"
            );
            FuzzConfig::default()
        }
    };

    tracing::info!(
        iterations = cfg.iterations,
        seed = format!("{:#x}", cfg.seed),
        modulus = cfg.field.modulus(),
        "ZK-FUZZ-HUNTER starting — hunting for under-constrained signals"
    );

    // System 1: the under-constrained victim (should be flagged).
    run_and_report(
        &under_constrained(),
        &under_constrained_witness(),
        &cfg,
    );

    // System 2: the properly-constrained control (should pass clean).
    run_and_report(
        &well_constrained(),
        &well_constrained_witness(),
        &cfg,
    );

    Ok(())
}

/// Fuzzes a single system and prints a human-readable verdict.
fn run_and_report(cs: &ConstraintSystem, honest: &[F], cfg: &FuzzConfig) {
    let report: Report = hunt(cs, honest, cfg.iterations, cfg.seed);

    tracing::info!(system = %cs.name, "----------------------------------------");

    if report.under_constrained {
        let (h, forged) = report
            .witness_collision
            .as_ref()
            .expect("collision present when under_constrained");
        tracing::warn!(
            iterations = report.iterations,
            signals = ?report.signals_flagged,
            "UNDER-CONSTRAINED — found forging witness"
        );
        tracing::warn!(honest = ?h, "  honest witness");
        tracing::warn!(forged = ?forged, "  forged witness (same public inputs, satisfies all constraints)");
        for &i in &report.signals_flagged {
            tracing::warn!(
                signal = i,
                honest = h[i],
                forged = forged[i],
                "  flagged signal differs"
            );
        }
    } else {
        tracing::info!(
            iterations = report.iterations,
            "OK — no collision found (no second witness satisfies the public inputs)"
        );
    }
}
