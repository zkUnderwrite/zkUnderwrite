//! zkUnderwrite issuer service.
//!
//! Plays the role a bank / payroll provider plays in production: it holds an
//! Ed25519 key and signs canonical income statements. The borrower feeds the
//! signed statement to the RISC Zero guest, which verifies this signature
//! *inside* the proof. The contract trusts issuers by `sha256(pubkey)`.
//!
//! Usage:
//!   zku-issuer keygen
//!     -> writes issuer_signing.bin (32B secret), issuer_pubkey.bin (32B),
//!        prints issuer_pubkey_hash (register this in the contract)
//!   zku-issuer sign <subject_id> <issuer_name> <m1> <m2> <m3>
//!     -> writes statement.json (exact signed bytes) + signature.bin (64B)

use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;

#[derive(Serialize)]
struct Statement {
    schema: &'static str,
    subject_id: String,
    issuer: String,
    currency: &'static str,
    issued_at: u64,
    period_months: u32,
    monthly_net_income: Vec<u64>,
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    match args.get(1).map(String::as_str) {
        Some("keygen") => keygen(),
        Some("sign") => sign(&args[2..]),
        _ => {
            eprintln!("usage: zku-issuer keygen | sign <subject_id> <issuer> <m1> <m2> <m3>");
            std::process::exit(2);
        }
    }
}

fn keygen() {
    let mut rng = rand::rngs::OsRng;
    let sk = SigningKey::generate(&mut rng);
    let vk: VerifyingKey = sk.verifying_key();
    fs::write("issuer_signing.bin", sk.to_bytes()).unwrap();
    fs::write("issuer_pubkey.bin", vk.to_bytes()).unwrap();
    let hash: [u8; 32] = Sha256::digest(vk.to_bytes()).into();
    println!("issuer_pubkey:      {}", hex::encode(vk.to_bytes()));
    println!("issuer_pubkey_hash: {}", hex::encode(hash));
}

fn sign(a: &[String]) {
    if a.len() < 5 {
        eprintln!("usage: zku-issuer sign <subject_id> <issuer> <m1> <m2> <m3>");
        std::process::exit(2);
    }
    let sk_bytes = fs::read("issuer_signing.bin").expect("run keygen first");
    let sk = SigningKey::from_bytes(&sk_bytes.as_slice().try_into().unwrap());

    let incomes: Vec<u64> = a[2..].iter().map(|s| s.parse().unwrap()).collect();
    let st = Statement {
        schema: "zku.income.v1",
        subject_id: a[0].clone(),
        issuer: a[1].clone(),
        currency: "USD",
        issued_at: 1_750_550_400,
        period_months: incomes.len() as u32,
        monthly_net_income: incomes,
    };
    // Canonical bytes = serde_json default serialization; the guest verifies the
    // signature over THESE exact bytes (read back from statement.json).
    let bytes = serde_json::to_vec(&st).unwrap();
    let sig = sk.sign(&bytes);
    fs::write("statement.json", &bytes).unwrap();
    fs::write("signature.bin", sig.to_bytes()).unwrap();
    println!("wrote statement.json ({} bytes) + signature.bin", bytes.len());
}
