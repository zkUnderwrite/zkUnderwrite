#![no_std]
//! # zkUnderwrite
//!
//! A privacy-preserving creditworthiness oracle on Stellar. A borrower submits a
//! RISC Zero Groth16 proof that their issuer-attested income meets a lender's
//! threshold — revealing no transactions and no identity — and this contract
//! verifies the proof and unlocks an undercollateralized USDC credit line.
//!
//! ## Soundness
//! - The contract stores the **expected guest image id** and passes *that* to the
//!   verifier (never a caller-supplied value), binding the proof to our exact
//!   guest program.
//! - It computes `sha256(journal_bytes)` itself and only then parses those same
//!   bytes, so the values it acts on are exactly the ones proven.
//! - A `nullifier` in the journal prevents proof reuse / Sybil.

use risc0_interface::RiscZeroVerifierRouterClient;
use soroban_sdk::{
    contract, contracterror, contractimpl, contracttype, panic_with_error, symbol_short, token,
    Address, Bytes, BytesN, Env,
};

/// Fixed journal layout produced by the guest (see DESIGN.md), total 81 bytes.
const JOURNAL_LEN: u32 = 81;
const OFF_ISSUER_HASH: u32 = 0; // [0,32)
const OFF_THRESHOLD: u32 = 32; // [32,40) u64 BE
const OFF_MEETS: u32 = 40; // [40] u8
const OFF_NULLIFIER: u32 = 41; // [41,73)
const OFF_PERIOD: u32 = 73; // [73,81) u64 BE

/// One Stellar ledger closes roughly every 5 seconds, so ~17280 ledgers per day.
const DAY_IN_LEDGERS: u32 = 17280;

/// Instance storage (`admin`, `router`, `expected_image_id`, `usdc`,
/// `required_threshold`, `credit_amount`) is read on every call, so it must
/// never be allowed to expire. Bump it whenever its remaining TTL drops below
/// 7 days, extending it back out to 30 days.
const INSTANCE_TTL_THRESHOLD: u32 = 7 * DAY_IN_LEDGERS;
const INSTANCE_TTL_EXTEND_TO: u32 = 30 * DAY_IN_LEDGERS;

/// Issuer registry entries and spent nullifiers are persistent storage and
/// must survive long gaps between admin/borrower activity: an expired issuer
/// entry silently un-registers a trusted issuer, and an expired nullifier
/// entry would let a previously-used proof be replayed. Bump whenever the
/// remaining TTL drops below 30 days, extending it out to 365 days (well
/// under the network max, but long enough to only need periodic renewal on
/// use rather than every call).
const PERSISTENT_TTL_THRESHOLD: u32 = 30 * DAY_IN_LEDGERS;
const PERSISTENT_TTL_EXTEND_TO: u32 = 365 * DAY_IN_LEDGERS;

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    NotInitialized = 1,
    AlreadyInitialized = 2,
    BadJournalLength = 3,
    IssuerNotRegistered = 4,
    ThresholdTooLow = 5,
    IncomeBelowThreshold = 6,
    NullifierAlreadyUsed = 7,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    Router,
    ImageId,
    Usdc,
    RequiredThreshold,
    CreditAmount,
    Issuer(BytesN<32>),     // presence => registered issuer (key = sha256(issuer_pubkey))
    Nullifier(BytesN<32>),  // presence => already spent
    CreditLine(Address),    // borrower => granted amount
}

#[contract]
pub struct ZkUnderwrite;

#[contractimpl]
impl ZkUnderwrite {
    /// Initialize the lender policy. `expected_image_id` is the RISC Zero guest
    /// program id; `router` is the deployed RISC Zero verifier router; `usdc` is
    /// the testnet USDC token contract this lender disburses.
    pub fn init(
        env: Env,
        admin: Address,
        router: Address,
        expected_image_id: BytesN<32>,
        usdc: Address,
        required_threshold: u64,
        credit_amount: i128,
    ) {
        let store = env.storage().instance();
        if store.has(&DataKey::Admin) {
            panic_with_error!(&env, Error::AlreadyInitialized);
        }
        admin.require_auth();
        store.set(&DataKey::Admin, &admin);
        store.set(&DataKey::Router, &router);
        store.set(&DataKey::ImageId, &expected_image_id);
        store.set(&DataKey::Usdc, &usdc);
        store.set(&DataKey::RequiredThreshold, &required_threshold);
        store.set(&DataKey::CreditAmount, &credit_amount);
        store.extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);
    }

    /// Register a trusted issuer by the sha256 hash of its Ed25519 public key.
    pub fn register_issuer(env: Env, issuer_pubkey_hash: BytesN<32>) {
        Self::assert_init(&env);
        let store = env.storage().instance();
        let admin: Address = store.get(&DataKey::Admin).unwrap();
        admin.require_auth();
        store.extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        let issuer_key = DataKey::Issuer(issuer_pubkey_hash);
        env.storage().persistent().set(&issuer_key, &true);
        env.storage().persistent().extend_ttl(
            &issuer_key,
            PERSISTENT_TTL_THRESHOLD,
            PERSISTENT_TTL_EXTEND_TO,
        );
    }

    /// Verify an income proof and, if valid and policy-compliant, disburse the
    /// credit line in USDC to `borrower`. Returns the granted amount.
    pub fn request_credit(env: Env, borrower: Address, seal: Bytes, journal: Bytes) -> i128 {
        borrower.require_auth();
        Self::assert_init(&env);
        let store = env.storage().instance();
        store.extend_ttl(INSTANCE_TTL_THRESHOLD, INSTANCE_TTL_EXTEND_TO);

        // 1. Verify the proof, bound to OUR guest image id (never caller-supplied).
        let image_id: BytesN<32> = store.get(&DataKey::ImageId).unwrap();
        let router: Address = store.get(&DataKey::Router).unwrap();
        let journal_digest: BytesN<32> = env.crypto().sha256(&journal).into();
        RiscZeroVerifierRouterClient::new(&env, &router).verify(&seal, &image_id, &journal_digest);

        // 2. Parse the proven journal bytes.
        if journal.len() != JOURNAL_LEN {
            panic_with_error!(&env, Error::BadJournalLength);
        }
        let issuer_hash = read_bytes32(&env, &journal, OFF_ISSUER_HASH);
        let threshold = read_u64_be(&journal, OFF_THRESHOLD);
        let meets = journal.get(OFF_MEETS).unwrap();
        let nullifier = read_bytes32(&env, &journal, OFF_NULLIFIER);
        let _period = read_u64_be(&journal, OFF_PERIOD);

        // 3. Policy checks.
        let issuer_key = DataKey::Issuer(issuer_hash);
        if !env.storage().persistent().has(&issuer_key) {
            panic_with_error!(&env, Error::IssuerNotRegistered);
        }
        env.storage().persistent().extend_ttl(
            &issuer_key,
            PERSISTENT_TTL_THRESHOLD,
            PERSISTENT_TTL_EXTEND_TO,
        );
        let required: u64 = store.get(&DataKey::RequiredThreshold).unwrap();
        if threshold < required {
            panic_with_error!(&env, Error::ThresholdTooLow);
        }
        if meets != 1 {
            panic_with_error!(&env, Error::IncomeBelowThreshold);
        }
        let null_key = DataKey::Nullifier(nullifier.clone());
        if env.storage().persistent().has(&null_key) {
            panic_with_error!(&env, Error::NullifierAlreadyUsed);
        }
        env.storage().persistent().set(&null_key, &true);
        env.storage().persistent().extend_ttl(
            &null_key,
            PERSISTENT_TTL_THRESHOLD,
            PERSISTENT_TTL_EXTEND_TO,
        );

        // 4. Disburse the real testnet USDC credit line from this contract's treasury.
        let amount: i128 = store.get(&DataKey::CreditAmount).unwrap();
        let usdc: Address = store.get(&DataKey::Usdc).unwrap();
        token::TokenClient::new(&env, &usdc).transfer(
            &env.current_contract_address(),
            &borrower,
            &amount,
        );
        env.storage()
            .persistent()
            .set(&DataKey::CreditLine(borrower.clone()), &amount);

        env.events()
            .publish((symbol_short!("credit"), borrower), amount);
        amount
    }

    /// Read a borrower's granted credit line (0 if none).
    pub fn credit_line(env: Env, borrower: Address) -> i128 {
        env.storage()
            .persistent()
            .get(&DataKey::CreditLine(borrower))
            .unwrap_or(0)
    }

    fn assert_init(env: &Env) {
        if !env.storage().instance().has(&DataKey::Admin) {
            panic_with_error!(env, Error::NotInitialized);
        }
    }
}

fn read_bytes32(env: &Env, b: &Bytes, off: u32) -> BytesN<32> {
    let mut arr = [0u8; 32];
    let mut i = 0u32;
    while i < 32 {
        arr[i as usize] = b.get(off + i).unwrap();
        i += 1;
    }
    BytesN::from_array(env, &arr)
}

fn read_u64_be(b: &Bytes, off: u32) -> u64 {
    let mut v: u64 = 0;
    let mut i = 0u32;
    while i < 8 {
        v = (v << 8) | (b.get(off + i).unwrap() as u64);
        i += 1;
    }
    v
}

#[cfg(test)]
mod test;
