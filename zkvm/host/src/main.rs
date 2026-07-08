// zkUnderwrite host (borrower side): runs the guest in the zkVM, produces a
// Groth16 receipt, and writes proof.txt with:
//   line1: seal (hex)            -> pass to contract `request_credit`
//   line2: image_id (hex)        -> must equal the value stored in the contract
//   line3: journal_digest (hex)  -> sha256(journal_bytes)
//   line4: journal_bytes (hex)   -> pass to contract `request_credit`
//
// NOTE: the generated method constant names depend on the guest package name in
// methods/guest/Cargo.toml. With guest package `zku-guest` they are
// `ZKU_GUEST_ELF` / `ZKU_GUEST_ID`. Adjust the `use methods::...` line to match.
use methods::{ZKU_GUEST_ELF, ZKU_GUEST_ID};
use risc0_ethereum_contracts::encode_seal;
use risc0_zkvm::{default_prover, sha::Digest, ExecutorEnv, ProverOpts};
use sha2::{Digest as _, Sha256};
use std::fs;

fn main() {
    // Cheap path: print the guest image id (32-byte hex) and exit — no proving.
    if std::env::args().any(|a| a == "--print-image-id") {
        let image_id: [u8; 32] = Digest::from(ZKU_GUEST_ID).as_bytes().try_into().unwrap();
        println!("{}", hex::encode(image_id));
        return;
    }

    let statement = fs::read("statement.json").expect("statement.json (exact signed bytes)");
    let signature = fs::read("signature.bin").expect("signature.bin (64 bytes)");
    let issuer_pk = fs::read("issuer_pubkey.bin").expect("issuer_pubkey.bin (32 bytes)");
    let threshold: u64 = std::env::var("THRESHOLD")
        .unwrap_or_else(|_| "3000".into())
        .parse()
        .unwrap();
    let period: u64 = std::env::var("PERIOD")
        .unwrap_or_else(|_| "202506".into())
        .parse()
        .unwrap();

    let exec_env = ExecutorEnv::builder()
        .write(&statement)
        .unwrap()
        .write(&signature)
        .unwrap()
        .write(&issuer_pk)
        .unwrap()
        .write(&threshold)
        .unwrap()
        .write(&period)
        .unwrap()
        .build()
        .unwrap();

    let prover = default_prover();
    let opts = ProverOpts::groth16();
    let receipt = prover
        .prove_with_opts(exec_env, ZKU_GUEST_ELF, &opts)
        .unwrap()
        .receipt;

    // Sanity: this verifies locally with the same image id before we go on-chain.
    receipt.verify(ZKU_GUEST_ID).expect("local receipt verification failed");

    let journal_bytes = receipt.journal.bytes.clone();
    let seal = encode_seal(&receipt).unwrap();
    let image_id: [u8; 32] = Digest::from(ZKU_GUEST_ID).as_bytes().try_into().unwrap();
    let journal_digest: [u8; 32] = Sha256::digest(&journal_bytes).into();

    let out = format!(
        "{}\n{}\n{}\n{}\n",
        hex::encode(seal),
        hex::encode(image_id),
        hex::encode(journal_digest),
        hex::encode(&journal_bytes),
    );
    fs::write("proof.txt", out).unwrap();
    println!("proof.txt written ({} journal bytes)", journal_bytes.len());
}
