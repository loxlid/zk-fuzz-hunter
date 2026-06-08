//! Fuzzer configuration, loaded from a TOML file (see `config.example.toml`).
//!
//! The knobs are deliberately small: how hard to fuzz (`iterations`), what RNG
//! `seed` to use for reproducibility, and which prime `field` to work over.
//! Mirrors the config style of the sibling `launchsniper` repo — defaults via
//! `#[serde(default = ...)]` so a minimal file still loads, plus a `validate`
//! pass and pure projection helpers.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::field::{F, P};

/// Which prime field the harness operates over.
///
/// Only the u128-safe Mersenne prime is wired up here (the whole point of the
/// educational model is to avoid bignums), but the enum leaves room to grow
/// toward real circuit fields without changing the config schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FieldChoice {
    /// `2^61 - 1`, the default u128-safe field.
    #[serde(rename = "mersenne61")]
    Mersenne61,
}

impl FieldChoice {
    /// The prime modulus for this field choice.
    pub fn modulus(self) -> F {
        match self {
            FieldChoice::Mersenne61 => P,
        }
    }
}

/// Top-level fuzzer configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FuzzConfig {
    /// Random-search budget: how many candidate witnesses to try before
    /// declaring a system clean. Structured mutations run first and are cheap.
    #[serde(default = "default_iterations")]
    pub iterations: u64,

    /// RNG seed, so every finding is reproducible from the report.
    #[serde(default = "default_seed")]
    pub seed: u64,

    /// Which prime field to fuzz over.
    #[serde(default = "default_field")]
    pub field: FieldChoice,
}

fn default_iterations() -> u64 {
    100_000
}

fn default_seed() -> u64 {
    0xF1E1D
}

fn default_field() -> FieldChoice {
    FieldChoice::Mersenne61
}

impl Default for FuzzConfig {
    fn default() -> Self {
        Self {
            iterations: default_iterations(),
            seed: default_seed(),
            field: default_field(),
        }
    }
}

impl FuzzConfig {
    /// Loads and validates configuration from a TOML file.
    pub fn load(path: impl AsRef<Path>) -> anyhow::Result<Self> {
        let raw = std::fs::read_to_string(path.as_ref()).map_err(|e| {
            anyhow::anyhow!("failed to read config {}: {e}", path.as_ref().display())
        })?;
        let cfg: FuzzConfig = toml::from_str(&raw)?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn validate(&self) -> anyhow::Result<()> {
        if self.iterations == 0 {
            anyhow::bail!("iterations must be positive");
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
        iterations = 50000
        seed = 42
        field = "mersenne61"
    "#;

    #[test]
    fn parses_full_config() {
        let cfg: FuzzConfig = toml::from_str(SAMPLE).unwrap();
        assert_eq!(cfg.iterations, 50_000);
        assert_eq!(cfg.seed, 42);
        assert_eq!(cfg.field, FieldChoice::Mersenne61);
    }

    #[test]
    fn parses_empty_config_with_defaults() {
        // Every field has a serde default, so an empty document still loads.
        let cfg: FuzzConfig = toml::from_str("").unwrap();
        assert_eq!(cfg.iterations, default_iterations());
        assert_eq!(cfg.seed, default_seed());
        assert_eq!(cfg.field, FieldChoice::Mersenne61);
    }

    #[test]
    fn field_choice_exposes_modulus() {
        let cfg = FuzzConfig::default();
        assert_eq!(cfg.field.modulus(), P);
    }

    #[test]
    fn validate_rejects_zero_iterations() {
        let cfg = FuzzConfig {
            iterations: 0,
            seed: 1,
            field: FieldChoice::Mersenne61,
        };
        assert!(cfg.validate().is_err());
    }

    #[test]
    fn default_config_is_valid() {
        assert!(FuzzConfig::default().validate().is_ok());
    }
}
