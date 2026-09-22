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
//!   zku-issuer sign <subject_id> <issuer_name> <period> <m1> <m2> <m3>
//!     -> writes statement.json (exact signed bytes) + signature.bin (64B)
//!
//! `period` (e.g. yyyymm) is signed by the issuer as part of the statement so
//! the guest can derive the nullifier's period from authenticated data instead
//! of trusting a host-supplied value at proving time.

use clap::{Parser, Subcommand};
use std::path::PathBuf;
use std::process::ExitCode;

#[derive(Serialize)]
struct Statement {
    schema: &'static str,
    subject_id: String,
    issuer: String,
    currency: &'static str,
    issued_at: u64,
    period: u64,
    period_months: u32,
    monthly_net_income: Vec<u64>,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("keygen") => keygen(),
        Some("sign") => sign(&args[2..]),
        _ => {
            eprintln!(
                "usage: zku-issuer keygen | sign <subject_id> <issuer> <period> <m1> <m2> <m3>"
            );
            std::process::exit(2);
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let dir = PathBuf::from(".");

fn sign(a: &[String]) {
    if a.len() < 6 {
        eprintln!("usage: zku-issuer sign <subject_id> <issuer> <period> <m1> <m2> <m3>");
        std::process::exit(2);
    }
    let sk_bytes = fs::read("issuer_signing.bin").expect("run keygen first");
    let sk = SigningKey::from_bytes(&sk_bytes.as_slice().try_into().unwrap());

    let period: u64 = a[2].parse().expect("period must be a u64 (e.g. yyyymm)");
    let incomes: Vec<u64> = a[3..].iter().map(|s| s.parse().unwrap()).collect();
    let st = Statement {
        schema: "zku.income.v1",
        subject_id: a[0].clone(),
        issuer: a[1].clone(),
        currency: "USD",
        issued_at: 1_750_550_400,
        period,
        period_months: incomes.len() as u32,
        monthly_net_income: incomes,
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}
