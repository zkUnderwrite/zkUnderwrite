// zkUnderwrite RISC Zero guest: proves issuer-attested income meets a threshold
// without revealing amounts or identity. Commits the 81-byte journal (DESIGN.md).
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use risc0_zkvm::guest::env;
use serde::Deserialize;
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
struct Statement {
    #[allow(dead_code)]
    schema: String,
    subject_id: String,
    issuer: String,
    #[allow(dead_code)]
    currency: String,
    #[allow(dead_code)]
    issued_at: u64,
    period_months: u32,
    monthly_net_income: Vec<u64>,
}

fn main() {
    // Inputs (written by host, in this order).
    let statement_bytes: Vec<u8> = env::read();
    let signature_bytes: Vec<u8> = env::read(); // 64 bytes
    let issuer_pubkey_bytes: Vec<u8> = env::read(); // 32 bytes
    let threshold: u64 = env::read();
    let period: u64 = env::read();

    // 1) Verify the issuer's Ed25519 signature over the EXACT statement bytes.
    let pk: [u8; 32] = issuer_pubkey_bytes
        .as_slice()
        .try_into()
        .expect("issuer pubkey must be 32 bytes");
    let vk = VerifyingKey::from_bytes(&pk).expect("invalid issuer pubkey");
    let sig_arr: [u8; 64] = signature_bytes
        .as_slice()
        .try_into()
        .expect("signature must be 64 bytes");
    let sig = Signature::from_bytes(&sig_arr);
    vk.verify(&statement_bytes, &sig)
        .expect("issuer signature verification failed");

    // 2) Parse the now-authenticated statement.
    let st: Statement = serde_json::from_slice(&statement_bytes).expect("malformed statement");
    assert_eq!(
        st.period_months as usize,
        st.monthly_net_income.len(),
        "period_months must match number of income entries"
    );

    // 3) Income logic: average over the period; require every month positive.
    let sum: u64 = st.monthly_net_income.iter().copied().sum();
    let avg = sum / (st.period_months as u64);
    let recurring = st.monthly_net_income.iter().all(|&m| m > 0);
    let meets = recurring && avg >= threshold;

    // 4) Nullifier (no identity revealed): sha256(subject_id | issuer | period_le).
    let mut h = Sha256::new();
    h.update(st.subject_id.as_bytes());
    h.update(b"|");
    h.update(st.issuer.as_bytes());
    h.update(b"|");
    h.update(period.to_le_bytes());
    let nullifier: [u8; 32] = h.finalize().into();

    let issuer_hash: [u8; 32] = Sha256::digest(&issuer_pubkey_bytes).into();

    // 5) Commit the fixed 81-byte journal.
    let mut journal = Vec::with_capacity(81);
    journal.extend_from_slice(&issuer_hash); // [0,32)
    journal.extend_from_slice(&threshold.to_be_bytes()); // [32,40)
    journal.push(if meets { 1 } else { 0 }); // [40]
    journal.extend_from_slice(&nullifier); // [41,73)
    journal.extend_from_slice(&period.to_be_bytes()); // [73,81)
    env::commit_slice(&journal);
}
