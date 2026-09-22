//! zkUnderwrite issuer CLI.
//!
//! Plays the role a bank / payroll provider plays in production: it holds an
//! Ed25519 key and signs canonical income statements. The borrower feeds the
//! signed statement to the RISC Zero guest, which verifies this signature
//! *inside* the proof. The contract trusts issuers by `sha256(pubkey)`.
//!
//! Usage:
//!   zku-issuer keygen
//!     -> writes issuer_signing.bin (32B secret, mode 0600), issuer_pubkey.bin (32B),
//!        prints issuer_pubkey_hash (register this in the contract)
//!   zku-issuer sign <subject_id> <issuer_name> <m1> <m2> <m3> [--issued-at <unix-seconds>]
//!     -> writes statement.json (exact signed bytes) + signature.bin (64B)
//!
//! This binary is a thin wrapper around the `zku_issuer` library, which does
//! the actual work and returns typed errors instead of panicking.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Parser)]
#[command(name = "zku-issuer", about = "zkUnderwrite issuer CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Generate an Ed25519 issuer signing key and public key.
    Keygen,
    /// Sign a canonical income statement.
    Sign {
        /// Opaque, issuer-scoped subject id.
        subject_id: String,
        /// Issuer name.
        issuer: String,
        /// Exactly 3 monthly net income values: m1 m2 m3.
        #[arg(num_args = 3)]
        incomes: Vec<String>,
        /// Unix timestamp for `issued_at` (defaults to the current time).
        #[arg(long)]
        issued_at: Option<u64>,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let dir = PathBuf::from(".");

    let result = match cli.command {
        Command::Keygen => zku_issuer::run_keygen(&dir).map(|report| {
            println!("issuer_pubkey:      {}", report.pubkey_hex);
            println!("issuer_pubkey_hash: {}", report.pubkey_hash_hex);
        }),
        Command::Sign {
            subject_id,
            issuer,
            incomes,
            issued_at,
        } => zku_issuer::run_sign(&dir, subject_id, issuer, &incomes, issued_at).map(|report| {
            println!(
                "wrote statement.json ({} bytes) + signature.bin",
                report.statement_len
            );
        }),
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
