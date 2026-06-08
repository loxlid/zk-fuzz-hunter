//! The under-constrained signal *hunter*.
//!
//! Given a [`ConstraintSystem`] and an honest witness that satisfies it, the
//! fuzzer holds the **public** signals fixed (those are what the verifier
//! checks and an attacker cannot change) and searches the space of **private**
//! signal assignments for a *second*, distinct witness that also satisfies
//! every constraint. If it finds one, the system is **under-constrained**: a
//! malicious prover could submit that alternate witness and forge an
//! otherwise-valid proof.
//!
//! ## Search strategy
//!
//! Brute-forcing a ~61-bit field at random would essentially never stumble
//! onto a collision, so a useful fuzzer mixes random exploration with a set of
//! *structured* mutations that mirror how real under-constrained bugs
//! manifest:
//!
//!   * **field negation** — `x -> p - x`. This is the classic `x*x = y`
//!     alias (`(-x)² = x²`) and the single most common quadratic
//!     under-constraint.
//!   * **small additive perturbations** — `x -> x ± k`, catching off-by-one
//!     and unbounded-range bugs.
//!   * **cross-signal copies** — assigning one private signal's honest value
//!     to another, catching missing "these must differ" constraints.
//!   * **uniform random field elements** — broad, seeded exploration.
//!
//! The RNG is seeded so a finding is always reproducible from the report.

use rand::rngs::StdRng;
use rand::{Rng, SeedableRng};

use crate::field::{fadd, fneg, fsub, F, P};
use crate::r1cs::ConstraintSystem;

/// The verdict for one system.
#[derive(Debug, Clone)]
pub struct Report {
    /// `true` if a distinct, satisfying alternate witness was found.
    pub under_constrained: bool,
    /// The colliding pair `(honest, forged)` when one was found.
    pub witness_collision: Option<(Vec<F>, Vec<F>)>,
    /// How many candidate witnesses were evaluated before stopping.
    pub iterations: u64,
    /// Private signal indices that differed in the colliding witness — the
    /// signals the circuit failed to pin down.
    pub signals_flagged: Vec<usize>,
}

impl Report {
    /// A clean bill of health: no collision found within the budget.
    fn ok(iterations: u64) -> Self {
        Self {
            under_constrained: false,
            witness_collision: None,
            iterations,
            signals_flagged: Vec::new(),
        }
    }
}

/// Returns the private indices whose values differ between two witnesses.
fn diff_private(cs: &ConstraintSystem, honest: &[F], cand: &[F]) -> Vec<usize> {
    cs.private_indices()
        .into_iter()
        .filter(|&i| honest.get(i) != cand.get(i))
        .collect()
}

/// Checks one candidate: it must satisfy the system, keep every public signal
/// equal to the honest value, and differ from the honest witness in at least
/// one private signal. On success returns the flagged private indices.
fn check_candidate(
    cs: &ConstraintSystem,
    honest: &[F],
    cand: &[F],
) -> Option<Vec<F>> {
    // Public signals (and the constant wire) must be untouched.
    if cand[0] != honest[0] {
        return None;
    }
    for &pi in &cs.public_indices {
        if cand.get(pi) != honest.get(pi) {
            return None;
        }
    }
    if !cs.is_satisfied(cand) {
        return None;
    }
    if cand == honest {
        return None;
    }
    Some(cand.to_vec())
}

/// Yields a batch of *structured* candidate witnesses derived from the honest
/// one. These encode the common under-constraint signatures so the fuzzer
/// finds real bugs quickly instead of relying on luck.
fn structured_candidates(cs: &ConstraintSystem, honest: &[F]) -> Vec<Vec<F>> {
    let privs = cs.private_indices();
    let mut out = Vec::new();

    // Single-signal mutations.
    for &i in &privs {
        // Field negation: x -> p - x  (the (-x)² = x² alias).
        let mut neg = honest.to_vec();
        neg[i] = fneg(honest[i]);
        out.push(neg);

        // Small additive perturbations.
        for k in [1u128, 2, 3] {
            let mut up = honest.to_vec();
            up[i] = fadd(honest[i], k);
            out.push(up);

            let mut down = honest.to_vec();
            down[i] = fsub(honest[i], k);
            out.push(down);
        }
    }

    // Cross-signal copies: assign signal j's honest value to signal i.
    for &i in &privs {
        for &j in &privs {
            if i != j && honest[i] != honest[j] {
                let mut swap = honest.to_vec();
                swap[i] = honest[j];
                out.push(swap);
            }
        }
    }

    out
}

/// Hunts for an under-constrained signal in `cs` given an `honest` witness.
///
/// `iterations` bounds the random-search budget (structured candidates are
/// always tried first and don't count against it until exhausted). `seed`
/// makes every run reproducible.
///
/// # Panics
/// Panics if `honest` does not actually satisfy `cs` — the caller must supply
/// a valid baseline, otherwise "find a *different* satisfying witness" is
/// meaningless.
pub fn hunt(cs: &ConstraintSystem, honest: &[F], iterations: u64, seed: u64) -> Report {
    assert!(
        cs.is_satisfied(honest),
        "honest witness must satisfy the system before fuzzing"
    );

    let mut evaluated: u64 = 0;

    // Phase 1: structured mutations (the high-signal candidates).
    for cand in structured_candidates(cs, honest) {
        evaluated += 1;
        if let Some(forged) = check_candidate(cs, honest, &cand) {
            let flagged = diff_private(cs, honest, &forged);
            return Report {
                under_constrained: true,
                witness_collision: Some((honest.to_vec(), forged)),
                iterations: evaluated,
                signals_flagged: flagged,
            };
        }
    }

    // Phase 2: seeded random exploration of the private signal space.
    let privs = cs.private_indices();
    let mut rng = StdRng::seed_from_u64(seed);
    while evaluated < iterations {
        evaluated += 1;
        let mut cand = honest.to_vec();
        // Mutate a random non-empty subset of the private signals.
        for &i in &privs {
            if rng.gen_bool(0.5) {
                cand[i] = rng.gen_range(0..P);
            }
        }
        if let Some(forged) = check_candidate(cs, honest, &cand) {
            let flagged = diff_private(cs, honest, &forged);
            return Report {
                under_constrained: true,
                witness_collision: Some((honest.to_vec(), forged)),
                iterations: evaluated,
                signals_flagged: flagged,
            };
        }
    }

    Report::ok(evaluated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r1cs::{
        under_constrained, under_constrained_witness, well_constrained,
        well_constrained_witness,
    };

    #[test]
    fn finds_collision_in_under_constrained_system() {
        let cs = under_constrained();
        let honest = under_constrained_witness();
        let report = hunt(&cs, &honest, 100_000, 0xF1E1D);

        assert!(
            report.under_constrained,
            "fuzzer MUST flag the under-constrained x*x=y system"
        );
        let (h, forged) = report
            .witness_collision
            .expect("expected a colliding witness pair");
        // Same public output...
        assert_eq!(h[2], forged[2], "public y must match");
        // ...but a different private x.
        assert_ne!(h[1], forged[1], "private x must differ");
        // And the forged x is exactly the field negation: p - 3.
        assert_eq!(forged[1], P - 3);
        // The flagged signal is x (index 1).
        assert_eq!(report.signals_flagged, vec![1]);
        // The forged witness genuinely satisfies the system.
        assert!(cs.is_satisfied(&forged));
    }

    #[test]
    fn finds_no_collision_in_well_constrained_system() {
        let cs = well_constrained();
        let honest = well_constrained_witness();
        let report = hunt(&cs, &honest, 200_000, 0xC0DE);

        assert!(
            !report.under_constrained,
            "fuzzer must NOT flag the properly-constrained system (no collision exists)"
        );
        assert!(report.witness_collision.is_none());
        assert!(report.signals_flagged.is_empty());
    }

    #[test]
    #[should_panic(expected = "honest witness must satisfy")]
    fn rejects_invalid_honest_witness() {
        let cs = under_constrained();
        let bogus = vec![1, 4, 9]; // 4*4 != 9
        let _ = hunt(&cs, &bogus, 100, 1);
    }
}
