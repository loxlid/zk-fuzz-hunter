# zk-fuzz-hunter

A circuit-constraint **fuzzing harness** that hunts for **under-constrained signals** in R1CS systems — the most dangerous and subtle bug class in zero-knowledge circuits. It models a simplified constraint system over a prime field, then fuzzes witness assignments to detect when a *malicious* witness satisfies every constraint yet differs from the honest one.

> ⚠️ **Educational / demo harness.** This is a *simplified* model of R1CS over a small u128-safe prime field. It illustrates the under-constrained bug class on toy systems — it is **not** a production circom/snark analyzer and makes no completeness guarantees. **Nothing here is a security audit.**

## What "under-constrained" means

A zero-knowledge proof convinces a verifier that a prover knows a *witness* (the private inputs) satisfying a set of constraints, without revealing it. Circuits are compiled to an **R1CS** (Rank-1 Constraint System): a list of constraints of the form

```
(Σ aᵢ·wᵢ) · (Σ bᵢ·wᵢ) = (Σ cᵢ·wᵢ)
```

over a finite field, where `w` is the full witness vector (public + private signals).

A signal is **under-constrained** when, for the *same public inputs*, **more than one** witness assignment satisfies all constraints. That sounds academic — it is catastrophic. If a second valid witness exists, a malicious prover can submit it and produce a proof the verifier accepts for a statement that was never actually proven. Depending on what the circuit guards, that means:

- **double-spends / forged balances** in a private rollup or mixer,
- **voting twice** under one identity in an anonymous-voting circuit,
- **minting** assets that were never deposited,
- **bypassing** range checks, membership proofs, or signature checks.

These bugs are insidious because the circuit still works perfectly for honest inputs and all positive tests pass. The hole only shows up when someone goes looking for the *alternate* witness.

## The canonical example

Consider a circuit that just enforces `x * x = y` and exposes `y` publicly:

```
x * x = y          // and nothing else
```

For `y = 9`, the honest prover uses `x = 3`. But over a field, `(-3)² = 9` as well — and `-3` is just `p - 3`, another valid field element. So `x = p - 3` is a *second* witness for the same public `y`. The signal `x` is under-constrained. The fix is to **pin** `x`, e.g. with a bit-decomposition (`x = Σ bᵢ·2ⁱ` with each `bᵢ` boolean), which rules out the negated alias.

This repo ships both systems as samples:

- `under_constrained()` — only `x*x=y`. The fuzzer **must** find the `x` / `-x` collision.
- `well_constrained()` — `x*x=y` **plus** a boolean bit-decomposition pinning `x`. The fuzzer **must not** find any collision.

The test suite asserts exactly that — it's the core proof the tool works.

## How the fuzzer works

Given a constraint system and an honest witness, the hunter:

1. **Holds public signals fixed** (the constant wire and every public index) — those are what the verifier checks; an attacker cannot change them.
2. **Mutates the private signals**, looking for a *second* assignment that still satisfies every constraint but differs in at least one private signal.

Random search over a ~61-bit field would essentially never get lucky, so the fuzzer leads with **structured mutations** that mirror how real under-constraints manifest, then falls back to seeded random exploration:

- **field negation** (`x → p − x`) — the classic quadratic alias,
- **small additive perturbations** (`x ± 1, 2, 3`) — off-by-one / unbounded range,
- **cross-signal copies** — missing "these must differ" constraints,
- **uniform random field elements** — broad, seeded exploration.

A finding is returned as a `Report { under_constrained, witness_collision, iterations, signals_flagged }`, with the seed making every collision reproducible.

## The field / R1CS model

Real circuits use ~254-bit primes (e.g. BN254). Carrying full bignums would add noise without changing the *shape* of the bug, so the harness uses the Mersenne prime `p = 2^61 − 1`. Every product of reduced elements stays under `2^122`, so all arithmetic fits in a `u128` — no bignum, no overflow. The field axioms (identities, inverses via Fermat, distributivity) are unit-tested in `field.rs`.

```
fuzzer/
  Cargo.toml
  src/
    main.rs      # CLI: load config, build both samples, fuzz, print verdicts
    config.rs    # TOML config (iterations, seed, field) — defaults + validation
    field.rs     # pure modular arithmetic over 2^61-1 (tested)
    r1cs.rs      # Constraint / ConstraintSystem + sample builders (tested)
    fuzzer.rs    # the hunter: structured + random witness search (tested)
```

## Build & run

```bash
cargo build
cargo test          # field axioms, R1CS satisfaction, collision detection
cargo run           # uses built-in defaults (or pass a config.toml path)
cargo run -- config.toml
```

Running prints two verdicts: `UNDER-CONSTRAINED — found forging witness` for the buggy sample (with the colliding `x` / `p−x` pair) and `OK — no collision found` for the properly-constrained one.

## Disclaimer

This is an educational model. A real circuit analyzer must reason symbolically over the actual constraint graph (or use a SAT/SMT solver) across the full witness space — random fuzzing on toy systems is illustrative, not exhaustive. Do not rely on it to clear a production circuit.

## License

MIT © 2026 Loxee
