//! A minimal Rank-1 Constraint System (R1CS) over the prime field in
//! [`crate::field`].
//!
//! An R1CS is a list of constraints, each of the form
//!
//! ```text
//! (Σ aᵢ·wᵢ) · (Σ bᵢ·wᵢ) = (Σ cᵢ·wᵢ)
//! ```
//!
//! where `w` is the *witness* vector (all signals, public and private) and
//! `a`, `b`, `c` are sparse linear combinations over `w`. This is exactly the
//! shape every SNARK back-end (Groth16, PLONK-ish, etc.) compiles a circuit
//! down to. Convention: `w[0] == 1` (the constant "one" wire) so that a linear
//! combination can encode constants by referencing index 0.
//!
//! The whole module is pure data + pure functions so the system can be
//! constructed, evaluated and audited without any I/O.

use crate::field::{fadd, fmul, F};

/// A sparse linear combination `Σ coeff·w[index]`, stored as `(index, coeff)`
/// pairs. Indices reference positions in the witness vector.
pub type Lc = Vec<(usize, F)>;

/// A single rank-1 constraint: `(A·w) * (B·w) = (C·w)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Constraint {
    pub a: Lc,
    pub b: Lc,
    pub c: Lc,
}

impl Constraint {
    /// Evaluates a linear combination against a witness vector.
    ///
    /// Out-of-range indices contribute nothing; this keeps builders forgiving
    /// while still being deterministic.
    fn eval_lc(lc: &Lc, witness: &[F]) -> F {
        let mut acc: F = 0;
        for &(idx, coeff) in lc {
            if let Some(&w) = witness.get(idx) {
                acc = fadd(acc, fmul(coeff, w));
            }
        }
        acc
    }

    /// Returns `true` iff this single constraint holds for `witness`.
    pub fn is_satisfied(&self, witness: &[F]) -> bool {
        let a = Self::eval_lc(&self.a, witness);
        let b = Self::eval_lc(&self.b, witness);
        let c = Self::eval_lc(&self.c, witness);
        fmul(a, b) == c
    }
}

/// A constraint system: the constraints plus bookkeeping about which witness
/// signals are *public* (fixed by the verifier) versus *private* (the prover's
/// secret, and therefore what an attacker is free to forge).
#[derive(Debug, Clone)]
pub struct ConstraintSystem {
    /// Human-readable label for diagnostics.
    pub name: String,
    /// Number of signals in the witness, including `w[0] == 1`.
    pub num_signals: usize,
    /// The constraints to satisfy.
    pub constraints: Vec<Constraint>,
    /// Witness indices that are public inputs/outputs (held fixed when
    /// fuzzing). Index `0` (the constant wire) is always implicitly public.
    pub public_indices: Vec<usize>,
}

impl ConstraintSystem {
    /// Returns `true` iff *every* constraint holds and the constant wire is
    /// pinned to `1` (a malformed `w[0]` would invalidate every constant).
    pub fn is_satisfied(&self, witness: &[F]) -> bool {
        if witness.len() != self.num_signals {
            return false;
        }
        if witness[0] != 1 {
            return false;
        }
        self.constraints.iter().all(|c| c.is_satisfied(witness))
    }

    /// Witness indices the fuzzer is allowed to mutate: everything that is not
    /// public and not the constant wire (index 0).
    pub fn private_indices(&self) -> Vec<usize> {
        (1..self.num_signals)
            .filter(|i| !self.public_indices.contains(i))
            .collect()
    }
}

/// Builds a **well-constrained** sample system.
///
/// Signals: `w = [1, x, y, b0, b1, b2]`
///   * `w[0] = 1`  (constant wire)
///   * `w[1] = x`  (private)
///   * `w[2] = y`  (public output)
///   * `w[3..6]`   3 bits of `x` (private)
///
/// Constraints:
///   1. `x * x = y`                       (the squaring relation)
///   2. `b0 * (b0 - 1) = 0`               (b0 is boolean)
///   3. `b1 * (b1 - 1) = 0`               (b1 is boolean)
///   4. `b2 * (b2 - 1) = 0`               (b2 is boolean)
///   5. `(b0 + 2·b1 + 4·b2) * 1 = x`      (bit-decomposition *pins* x)
///
/// Constraint 5 is the crucial difference from the buggy system: by forcing
/// `x` to equal a specific non-negative bit-decomposition, it rules out the
/// `-x` (i.e. `p - x`) alias that would otherwise also square to `y`. With `x`
/// uniquely pinned, the honest witness is the *only* satisfying assignment for
/// a given public `y`. Here we model `x = 3` (`y = 9`, bits `1,1,0`).
pub fn well_constrained() -> ConstraintSystem {
    // Indices.
    let one = 0;
    let x = 1;
    let _y = 2;
    let b0 = 3;
    let b1 = 4;
    let b2 = 5;

    let bool_constraint = |bit: usize| Constraint {
        // bit * (bit - 1) = 0  ==>  A = bit, B = bit - 1, C = 0
        a: vec![(bit, 1)],
        b: vec![(bit, 1), (one, crate::field::fneg(1))],
        c: vec![],
    };

    let constraints = vec![
        // 1. x * x = y
        Constraint {
            a: vec![(x, 1)],
            b: vec![(x, 1)],
            c: vec![(2, 1)],
        },
        // 2-4. booleanity of each bit
        bool_constraint(b0),
        bool_constraint(b1),
        bool_constraint(b2),
        // 5. (b0 + 2·b1 + 4·b2) * 1 = x   — pins x to its bit-decomposition
        Constraint {
            a: vec![(b0, 1), (b1, 2), (b2, 4)],
            b: vec![(one, 1)],
            c: vec![(x, 1)],
        },
    ];

    ConstraintSystem {
        name: "well_constrained (x*x=y, x pinned by bit-decomposition)".to_string(),
        num_signals: 6,
        constraints,
        public_indices: vec![2], // y is the public output
    }
}

/// The honest witness for [`well_constrained`]: `x = 3`, `y = 9`, bits `1,1,0`.
pub fn well_constrained_witness() -> Vec<F> {
    // w = [1, x=3, y=9, b0=1, b1=1, b2=0]
    vec![1, 3, 9, 1, 1, 0]
}

/// Builds an **under-constrained** sample system — the bug we hunt.
///
/// Signals: `w = [1, x, y]`
///   * `w[0] = 1`  (constant wire)
///   * `w[1] = x`  (private)
///   * `w[2] = y`  (public output)
///
/// Constraint: `x * x = y`  — and nothing else.
///
/// This is the textbook under-constrained circuit. For a public `y = 9`, both
/// `x = 3` *and* `x = p - 3` (the field's `-3`) satisfy `x*x = 9`, because
/// `(-3)² = 9` in the field too. A malicious prover can therefore present a
/// *different* private witness that the verifier still accepts — exactly the
/// kind of forgeability that lets an attacker mint, double-spend, or vote
/// twice depending on what the circuit was guarding.
pub fn under_constrained() -> ConstraintSystem {
    let x = 1;
    let y = 2;

    let constraints = vec![Constraint {
        // x * x = y
        a: vec![(x, 1)],
        b: vec![(x, 1)],
        c: vec![(y, 1)],
    }];

    ConstraintSystem {
        name: "under_constrained (only x*x=y — x and -x both satisfy)".to_string(),
        num_signals: 3,
        constraints,
        public_indices: vec![2], // y is public; x is free to forge
    }
}

/// The honest witness for [`under_constrained`]: `x = 3`, `y = 9`.
pub fn under_constrained_witness() -> Vec<F> {
    vec![1, 3, 9]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::field::{fneg, P};

    #[test]
    fn well_constrained_honest_witness_satisfies() {
        let cs = well_constrained();
        assert!(cs.is_satisfied(&well_constrained_witness()));
    }

    #[test]
    fn well_constrained_rejects_negated_x() {
        // The whole point: -x (= p - 3) must FAIL because the bit-decomposition
        // pins x to 3, and p-3 has no valid 3-bit decomposition.
        let cs = well_constrained();
        let mut bad = well_constrained_witness();
        bad[1] = fneg(3); // x := -3
        assert!(!cs.is_satisfied(&bad), "negated x should not satisfy");
    }

    #[test]
    fn well_constrained_rejects_wrong_y() {
        let cs = well_constrained();
        let mut bad = well_constrained_witness();
        bad[2] = 10; // y := 10, but 3*3 = 9
        assert!(!cs.is_satisfied(&bad));
    }

    #[test]
    fn well_constrained_rejects_non_boolean_bit() {
        let cs = well_constrained();
        let mut bad = well_constrained_witness();
        bad[3] = 2; // b0 must be 0 or 1
        assert!(!cs.is_satisfied(&bad));
    }

    #[test]
    fn under_constrained_honest_witness_satisfies() {
        let cs = under_constrained();
        assert!(cs.is_satisfied(&under_constrained_witness()));
    }

    #[test]
    fn under_constrained_also_accepts_negated_x() {
        // This is the forgeable alias: -x squares to the same y.
        let cs = under_constrained();
        let forged = vec![1, fneg(3), 9]; // x := -3, y := 9
        assert!(
            cs.is_satisfied(&forged),
            "under-constrained system must (wrongly) accept -x"
        );
        // And the forged x genuinely differs from the honest one.
        assert_ne!(fneg(3), 3);
        assert_eq!(fneg(3), P - 3);
    }

    #[test]
    fn under_constrained_rejects_bad_square() {
        let cs = under_constrained();
        let bad = vec![1, 4, 9]; // 4*4 = 16 != 9
        assert!(!cs.is_satisfied(&bad));
    }

    #[test]
    fn wrong_constant_wire_invalidates_system() {
        let cs = under_constrained();
        let mut bad = under_constrained_witness();
        bad[0] = 2; // constant wire must be 1
        assert!(!cs.is_satisfied(&bad));
    }

    #[test]
    fn private_indices_excludes_public_and_constant() {
        let cs = under_constrained();
        assert_eq!(cs.private_indices(), vec![1]); // only x
        let cs2 = well_constrained();
        assert_eq!(cs2.private_indices(), vec![1, 3, 4, 5]); // x + 3 bits
    }
}
