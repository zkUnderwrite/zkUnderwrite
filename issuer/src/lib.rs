//! Library implementation behind the `zku-issuer` CLI.
//!
//! Holds an Ed25519 key and signs canonical income statements. The guest
//! program (see `zkvm/methods/guest/src/main.rs`) deserializes the exact
//! bytes this crate writes to `statement.json`, so the `Statement` field
//! set, types and serialization must stay byte-for-byte compatible with
//! what the guest expects. Do not reorder, rename or retype the fields
//! below without also updating the guest.

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use zeroize::Zeroize;

/// File names written by `keygen` / read and written by `sign`.
pub const SIGNING_KEY_FILE: &str = "issuer_signing.bin";
pub const PUBKEY_FILE: &str = "issuer_pubkey.bin";
pub const STATEMENT_FILE: &str = "statement.json";
pub const SIGNATURE_FILE: &str = "signature.bin";

/// `sign` documents (and requires) exactly this many monthly income values:
/// `m1 m2 m3`.
pub const EXPECTED_MONTHS: usize = 3;

/// Typed errors returned by this library. Replaces the panics/unwraps the
/// CLI used to hit on bad input or I/O failures.
#[derive(Debug, thiserror::Error)]
pub enum IssuerError {
    #[error("failed to read {path}: {source}")]
    ReadFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to write {path}: {source}")]
    WriteFile {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("failed to set permissions on {path}: {source}")]
    SetPermissions {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("signing key at {path} must be {expected} bytes, found {actual}; run `keygen` again")]
    InvalidKeyLength {
        path: PathBuf,
        expected: usize,
        actual: usize,
    },
    #[error("expected exactly {expected} monthly income values (m1..m{expected}), got {actual}")]
    InvalidMonthCount { expected: usize, actual: usize },
    #[error("invalid monthly income value {value:?}: {source}")]
    InvalidIncome {
        value: String,
        #[source]
        source: std::num::ParseIntError,
    },
    #[error("failed to serialize statement: {0}")]
    Serialize(#[from] serde_json::Error),
}

/// The signed income statement. Field order and types are load-bearing:
/// the issuer signs `serde_json::to_vec(&Statement)` verbatim and the guest
/// verifies the signature over those exact bytes before parsing them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Statement {
    pub schema: String,
    pub subject_id: String,
    pub issuer: String,
    pub currency: String,
    pub issued_at: u64,
    pub period_months: u32,
    pub monthly_net_income: Vec<u64>,
}

/// Result of `run_keygen`, for the CLI to print.
pub struct KeygenReport {
    pub pubkey_hex: String,
    pub pubkey_hash_hex: String,
}

/// Result of `run_sign`, for the CLI to print.
pub struct SignReport {
    pub statement_len: usize,
}

/// Generate a new Ed25519 issuer signing key and write it (mode 0600 on
/// unix) plus the corresponding public key to `dir`.
pub fn run_keygen(dir: &Path) -> Result<KeygenReport, IssuerError> {
    let mut rng = rand::rngs::OsRng;
    let sk = SigningKey::generate(&mut rng);
    let vk: VerifyingKey = sk.verifying_key();

    let mut sk_bytes = sk.to_bytes();
    let signing_key_path = dir.join(SIGNING_KEY_FILE);
    write_file(&signing_key_path, &sk_bytes)?;
    restrict_permissions(&signing_key_path)?;
    // Best-effort zeroization: this clears our local copy of the secret
    // bytes once they are on disk. `SigningKey` itself is built with the
    // `zeroize` feature of `ed25519-dalek`, which zeroes its own internal
    // copy on drop, but neither can scrub copies the OS/allocator may have
    // made (e.g. via swap, or temporaries produced by `rand`/serde on the
    // way here) -- that is a limitation of process memory, not something
    // this crate can fully close.
    sk_bytes.zeroize();

    let pubkey_path = dir.join(PUBKEY_FILE);
    write_file(&pubkey_path, &vk.to_bytes())?;

    let hash: [u8; 32] = Sha256::digest(vk.to_bytes()).into();
    Ok(KeygenReport {
        pubkey_hex: hex::encode(vk.to_bytes()),
        pubkey_hash_hex: hex::encode(hash),
    })
}

/// Sign a canonical income statement using the key written by `keygen` in
/// `dir`, and write `statement.json` + `signature.bin` to `dir`.
pub fn run_sign(
    dir: &Path,
    subject_id: String,
    issuer: String,
    incomes_raw: &[String],
    issued_at: Option<u64>,
) -> Result<SignReport, IssuerError> {
    let incomes = parse_incomes(incomes_raw)?;
    let issued_at = issued_at.unwrap_or_else(current_unix_time);

    let signing_key_path = dir.join(SIGNING_KEY_FILE);
    let mut sk_bytes = read_file(&signing_key_path)?;
    let sk_array: [u8; 32] =
        sk_bytes
            .as_slice()
            .try_into()
            .map_err(|_| IssuerError::InvalidKeyLength {
                path: signing_key_path.clone(),
                expected: 32,
                actual: sk_bytes.len(),
            })?;
    sk_bytes.zeroize();
    let sk = SigningKey::from_bytes(&sk_array);

    let statement = build_statement(subject_id, issuer, incomes, issued_at);
    // Canonical bytes = serde_json default serialization; the guest verifies
    // the signature over THESE exact bytes (read back from statement.json).
    let bytes = serialize_statement(&statement)?;
    let sig = sk.sign(&bytes);

    write_file(&dir.join(STATEMENT_FILE), &bytes)?;
    write_file(&dir.join(SIGNATURE_FILE), &sig.to_bytes())?;

    Ok(SignReport {
        statement_len: bytes.len(),
    })
}

/// Parse and validate the raw `sign` income arguments: exactly
/// [`EXPECTED_MONTHS`] values, each a valid `u64`.
pub fn parse_incomes(raw: &[String]) -> Result<Vec<u64>, IssuerError> {
    if raw.len() != EXPECTED_MONTHS {
        return Err(IssuerError::InvalidMonthCount {
            expected: EXPECTED_MONTHS,
            actual: raw.len(),
        });
    }
    raw.iter()
        .map(|s| {
            s.parse::<u64>().map_err(|source| IssuerError::InvalidIncome {
                value: s.clone(),
                source,
            })
        })
        .collect()
}

/// Build the `Statement` for `sign`. `period_months` is derived from the
/// income vector so the two can never disagree (the guest asserts they
/// match).
pub fn build_statement(
    subject_id: String,
    issuer: String,
    monthly_net_income: Vec<u64>,
    issued_at: u64,
) -> Statement {
    Statement {
        schema: "zku.income.v1".to_string(),
        subject_id,
        issuer,
        currency: "USD".to_string(),
        issued_at,
        period_months: monthly_net_income.len() as u32,
        monthly_net_income,
    }
}

/// Serialize a `Statement` to the exact bytes that get signed and that the
/// guest later verifies/parses. Do not change this without updating the
/// guest's `Statement` deserialization in lockstep.
pub fn serialize_statement(st: &Statement) -> Result<Vec<u8>, IssuerError> {
    Ok(serde_json::to_vec(st)?)
}

fn current_unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn read_file(path: &Path) -> Result<Vec<u8>, IssuerError> {
    std::fs::read(path).map_err(|source| IssuerError::ReadFile {
        path: path.to_path_buf(),
        source,
    })
}

fn write_file(path: &Path, bytes: &[u8]) -> Result<(), IssuerError> {
    std::fs::write(path, bytes).map_err(|source| IssuerError::WriteFile {
        path: path.to_path_buf(),
        source,
    })
}

#[cfg(unix)]
fn restrict_permissions(path: &Path) -> Result<(), IssuerError> {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(|source| {
        IssuerError::SetPermissions {
            path: path.to_path_buf(),
            source,
        }
    })
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &Path) -> Result<(), IssuerError> {
    Ok(())
}

