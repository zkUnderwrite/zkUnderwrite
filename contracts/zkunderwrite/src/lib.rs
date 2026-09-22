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

#[contracterror]
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
#[repr(u32)]
pub enum Error {
    /// `init` has not been called yet, so no policy/state is set.
    NotInitialized = 1,
    /// `init` was called a second time; the contract can only be initialized once.
    AlreadyInitialized = 2,
    /// The proven `journal` was not exactly `JOURNAL_LEN` (81) bytes.
    BadJournalLength = 3,
    /// The journal's `issuer_pubkey_hash` is not in the registered-issuer set.
    IssuerNotRegistered = 4,
    /// The proven `threshold` is below this lender's `required_threshold`.
    ThresholdTooLow = 5,
    /// The journal's `income_meets_threshold` flag was `0` (not met).
    IncomeBelowThreshold = 6,
    /// The journal's `nullifier` has already been spent (replay/Sybil guard).
    NullifierAlreadyUsed = 7,
    InvalidCreditAmount = 8,
    InvalidThreshold = 9,
    InvalidImageId = 10,
    BadJournal = 11,
    NoPendingAdmin = 12,
}

#[contracttype]
#[derive(Clone)]
pub enum DataKey {
    Admin,
    PendingAdmin,
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
        if credit_amount <= 0 {
            panic_with_error!(&env, Error::InvalidCreditAmount);
        }
        if required_threshold == 0 {
            panic_with_error!(&env, Error::InvalidThreshold);
        }
        if expected_image_id == BytesN::from_array(&env, &[0u8; 32]) {
            panic_with_error!(&env, Error::InvalidImageId);
        }
        admin.require_auth();
        store.set(&DataKey::Admin, &admin);
        store.set(&DataKey::Router, &router);
        store.set(&DataKey::ImageId, &expected_image_id);
        store.set(&DataKey::Usdc, &usdc);
        store.set(&DataKey::RequiredThreshold, &required_threshold);
        store.set(&DataKey::CreditAmount, &credit_amount);
    }

    /// Register a trusted issuer by the sha256 hash of its Ed25519 public key.
    pub fn register_issuer(env: Env, issuer_pubkey_hash: BytesN<32>) {
        Self::assert_init(&env);
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NotInitialized));
        admin.require_auth();
        env.storage()
            .persistent()
            .set(&DataKey::Issuer(issuer_pubkey_hash.clone()), &true);
        env.events()
            .publish((symbol_short!("iss_reg"), issuer_pubkey_hash), admin);
    }

    /// Revoke a previously registered issuer by the sha256 hash of its Ed25519
    /// public key. Admin only. Removing an issuer that was never registered is
    /// a no-op, matching `register_issuer`'s idempotent set.
    pub fn unregister_issuer(env: Env, issuer_hash: BytesN<32>) {
        Self::assert_init(&env);
        let admin: Address = env
            .storage()
            .instance()
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NotInitialized));
        admin.require_auth();
        env.storage()
            .persistent()
            .remove(&DataKey::Issuer(issuer_hash.clone()));
        env.events()
            .publish((symbol_short!("iss_unreg"), issuer_hash), admin);
    }

    /// Step 1 of admin rotation: the current admin proposes `new_admin`. The
    /// transfer only completes once `new_admin` calls `accept_admin`, so a
    /// typo'd or unreachable address can never brick admin control.
    pub fn propose_admin(env: Env, new_admin: Address) {
        Self::assert_init(&env);
        let store = env.storage().instance();
        let admin: Address = store
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NotInitialized));
        admin.require_auth();
        store.set(&DataKey::PendingAdmin, &new_admin);
        env.events()
            .publish((symbol_short!("adm_prop"), admin), new_admin);
    }

    /// Step 2 of admin rotation: the proposed address proves control by
    /// authorizing this call itself, then becomes the new admin.
    pub fn accept_admin(env: Env) {
        Self::assert_init(&env);
        let store = env.storage().instance();
        let pending: Address = store
            .get(&DataKey::PendingAdmin)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NoPendingAdmin));
        pending.require_auth();
        let old_admin: Address = store
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NotInitialized));
        store.set(&DataKey::Admin, &pending);
        store.remove(&DataKey::PendingAdmin);
        env.events()
            .publish((symbol_short!("adm_acc"), old_admin), pending);
    }

    /// Let the current admin withdraw a pending proposal before it is
    /// accepted, e.g. after proposing the wrong address.
    pub fn cancel_admin_proposal(env: Env) {
        Self::assert_init(&env);
        let store = env.storage().instance();
        let admin: Address = store
            .get(&DataKey::Admin)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NotInitialized));
        admin.require_auth();
        let pending: Address = store
            .get(&DataKey::PendingAdmin)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NoPendingAdmin));
        store.remove(&DataKey::PendingAdmin);
        env.events()
            .publish((symbol_short!("adm_cncl"), admin), pending);
    }

    /// Verify an income proof and, if valid and policy-compliant, disburse the
    /// credit line in USDC to `borrower`. Returns the granted amount.
    pub fn request_credit(env: Env, borrower: Address, seal: Bytes, journal: Bytes) -> i128 {
        borrower.require_auth();
        Self::assert_init(&env);
        let store = env.storage().instance();

        // 1. Check the journal shape BEFORE spending a verifier call on it.
        if journal.len() != JOURNAL_LEN {
            panic_with_error!(&env, Error::BadJournalLength);
        }

        // 2. Verify the proof, bound to OUR guest image id (never caller-supplied).
        let image_id: BytesN<32> = store
            .get(&DataKey::ImageId)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NotInitialized));
        let router: Address = store
            .get(&DataKey::Router)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NotInitialized));
        let journal_digest: BytesN<32> = env.crypto().sha256(&journal).into();
        RiscZeroVerifierRouterClient::new(&env, &router).verify(&seal, &image_id, &journal_digest);

        // 3. Parse the proven journal bytes.
        let issuer_hash = read_bytes32(&env, &journal, OFF_ISSUER_HASH);
        let threshold = read_u64_be(&env, &journal, OFF_THRESHOLD);
        let meets = journal
            .get(OFF_MEETS)
            .unwrap_or_else(|| panic_with_error!(&env, Error::BadJournal));
        let nullifier = read_bytes32(&env, &journal, OFF_NULLIFIER);
        let _period = read_u64_be(&env, &journal, OFF_PERIOD);

        // 4. Policy checks.
        if !env
            .storage()
            .persistent()
            .has(&DataKey::Issuer(issuer_hash))
        {
            panic_with_error!(&env, Error::IssuerNotRegistered);
        }
        let required: u64 = store
            .get(&DataKey::RequiredThreshold)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NotInitialized));
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

        // 5. Disburse the real testnet USDC credit line from this contract's treasury.
        let amount: i128 = store
            .get(&DataKey::CreditAmount)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NotInitialized));
        let usdc: Address = store
            .get(&DataKey::Usdc)
            .unwrap_or_else(|| panic_with_error!(&env, Error::NotInitialized));
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
        arr[i as usize] = b
            .get(off + i)
            .unwrap_or_else(|| panic_with_error!(env, Error::BadJournal));
        i += 1;
    }
    BytesN::from_array(env, &arr)
}

fn read_u64_be(env: &Env, b: &Bytes, off: u32) -> u64 {
    let mut v: u64 = 0;
    let mut i = 0u32;
    while i < 8 {
        v = (v << 8)
            | (b
                .get(off + i)
                .unwrap_or_else(|| panic_with_error!(env, Error::BadJournal)) as u64);
        i += 1;
    }
    v
}

#[cfg(test)]
mod test;
