//! Modular arithmetic over a prime field `F_p`.
//!
//! Everything here is a *pure function* over field elements (`F`, a `u128`
//! kept reduced mod `p`). Keeping the arithmetic pure and small makes it
//! trivially unit-testable — which matters a lot, because the whole fuzzer is
//! only as trustworthy as the field math underneath it.
//!
//! ## Why a small prime?
//!
//! Real ZK circuits work over huge primes (e.g. the ~254-bit BN254 scalar
//! field). Carrying full bignums here would add a lot of noise for no
//! conceptual gain — the *under-constrained* bug class we hunt for is about
//! the *shape* of the constraints, not the size of the modulus. So we use a
//! Mersenne prime that keeps every intermediate product inside a `u128`:
//!
//! ```text
//! p = 2^61 - 1 = 2_305_843_009_213_693_951   (a prime)
//! ```
//!
//! With `p < 2^61`, any product `a * b` with `a, b < p` is `< 2^122`, which
//! fits comfortably in a `u128`. No overflow, no bignum, no drama.

/// A field element, always stored reduced into `0..p`.
pub type F = u128;

/// The default field modulus: the Mersenne prime `2^61 - 1`.
///
/// Small enough that products stay inside a `u128`, large enough that random
/// fuzzing won't stumble onto collisions by luck.
pub const P: F = 2_305_843_009_213_693_951; // 2^61 - 1

/// Reduces an arbitrary `u128` into the field `0..p`.
#[inline]
pub fn fnorm(a: F) -> F {
    a % P
}

/// Field addition: `(a + b) mod p`.
///
/// Inputs are reduced first so callers can pass any `u128`; the sum of two
/// reduced elements is `< 2p < 2^62`, well within `u128`.
#[inline]
pub fn fadd(a: F, b: F) -> F {
    (fnorm(a) + fnorm(b)) % P
}

/// Field subtraction: `(a - b) mod p`, kept non-negative.
#[inline]
pub fn fsub(a: F, b: F) -> F {
    let a = fnorm(a);
    let b = fnorm(b);
    (a + P - b) % P
}

/// Field multiplication: `(a * b) mod p`.
///
/// Both operands are reduced to `< p < 2^61`, so the product is `< 2^122` and
/// fits in a `u128` with no overflow.
#[inline]
pub fn fmul(a: F, b: F) -> F {
    (fnorm(a) * fnorm(b)) % P
}

/// The additive inverse (negation): `(-a) mod p`.
#[inline]
pub fn fneg(a: F) -> F {
    let a = fnorm(a);
    if a == 0 {
        0
    } else {
        P - a
    }
}

/// Modular exponentiation `base^exp mod p` by square-and-multiply.
pub fn fpow(base: F, mut exp: u128) -> F {
    let mut result: F = 1;
    let mut b = fnorm(base);
    while exp > 0 {
        if exp & 1 == 1 {
            result = fmul(result, b);
        }
        b = fmul(b, b);
        exp >>= 1;
    }
    result
}

/// The multiplicative inverse via Fermat's little theorem: for prime `p` and
/// `a != 0`, `a^(p-2) ≡ a^{-1} (mod p)`.
///
/// Returns `None` for `0`, which has no inverse.
pub fn finv(a: F) -> Option<F> {
    let a = fnorm(a);
    if a == 0 {
        None
    } else {
        Some(fpow(a, P - 2))
    }
}

/// Field division `a / b = a * b^{-1}`. Returns `None` when `b == 0`.
pub fn fdiv(a: F, b: F) -> Option<F> {
    finv(b).map(|inv| fmul(a, inv))
}

#[cfg(test)]
mod tests {
    use super::*;

    // A handful of representative elements, including edge cases near `p`.
    fn samples() -> Vec<F> {
        vec![0, 1, 2, 7, 42, 1000, P - 1, P - 2, P / 2, 123_456_789]
    }

    #[test]
    fn additive_identity() {
        for &a in &samples() {
            assert_eq!(fadd(a, 0), fnorm(a), "a + 0 = a failed for {a}");
        }
    }

    #[test]
    fn multiplicative_identity() {
        for &a in &samples() {
            assert_eq!(fmul(a, 1), fnorm(a), "a * 1 = a failed for {a}");
        }
    }

    #[test]
    fn additive_inverse() {
        for &a in &samples() {
            assert_eq!(fadd(a, fneg(a)), 0, "a + (-a) = 0 failed for {a}");
        }
    }

    #[test]
    fn multiplicative_inverse() {
        for &a in &samples() {
            match finv(a) {
                Some(inv) => assert_eq!(fmul(a, inv), 1, "a * inv(a) = 1 failed for {a}"),
                None => assert_eq!(a, 0, "only 0 should have no inverse"),
            }
        }
    }

    #[test]
    fn zero_has_no_inverse() {
        assert_eq!(finv(0), None);
        assert_eq!(fdiv(5, 0), None);
    }

    #[test]
    fn commutativity() {
        let pairs = [(3, 5), (P - 1, 9), (42, 1000), (123_456, 7)];
        for &(a, b) in &pairs {
            assert_eq!(fadd(a, b), fadd(b, a), "addition commutativity");
            assert_eq!(fmul(a, b), fmul(b, a), "multiplication commutativity");
        }
    }

    #[test]
    fn distributivity() {
        // a * (b + c) == a*b + a*c
        let triples = [(3, 5, 7), (P - 1, 2, 9), (1000, 42, P - 3), (11, 13, 17)];
        for &(a, b, c) in &triples {
            let lhs = fmul(a, fadd(b, c));
            let rhs = fadd(fmul(a, b), fmul(a, c));
            assert_eq!(lhs, rhs, "distributivity failed for ({a},{b},{c})");
        }
    }

    #[test]
    fn subtraction_is_inverse_of_addition() {
        let pairs = [(10, 3), (3, 10), (0, 1), (P - 1, P - 2)];
        for &(a, b) in &pairs {
            // (a - b) + b == a
            assert_eq!(fadd(fsub(a, b), b), fnorm(a), "sub/add roundtrip");
        }
    }

    #[test]
    fn pow_matches_repeated_multiplication() {
        // 3^5 = 243
        assert_eq!(fpow(3, 5), 243);
        // 2^10 = 1024
        assert_eq!(fpow(2, 10), 1024);
        // anything^0 = 1
        assert_eq!(fpow(123_456, 0), 1);
        // 0^n = 0 for n > 0
        assert_eq!(fpow(0, 7), 0);
    }

    #[test]
    fn fermat_little_theorem() {
        // For a != 0, a^(p-1) == 1.
        for &a in &[1, 2, 7, 42, P - 1] {
            assert_eq!(fpow(a, P - 1), 1, "Fermat failed for {a}");
        }
    }
}
