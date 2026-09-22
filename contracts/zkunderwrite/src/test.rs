#![cfg(test)]
use super::*;
use soroban_sdk::{
    contract, contractimpl,
    testutils::{Address as _, MockAuth, MockAuthInvoke},
    token, Address, Bytes, BytesN, Env, IntoVal,
};

/// Stub verifier-router that always accepts — stands in for the deployed RISC
/// Zero router so we can exercise the full `request_credit` path (journal checks,
/// issuer registry, nullifier, real token transfer) without a real proof.
/// Returning `()` is wire-compatible with the router's `Result<(), _>` (both
/// encode success as Void).
#[contract]
pub struct StubRouter;

#[contractimpl]
impl StubRouter {
    pub fn verify(_env: Env, _seal: Bytes, _image_id: BytesN<32>, _journal: BytesN<32>) {}
}

/// Build an 81-byte journal in the contract's expected layout.
fn journal(
    env: &Env,
    issuer_hash: [u8; 32],
    threshold: u64,
    meets: u8,
    nullifier: [u8; 32],
    period: u64,
) -> Bytes {
    let mut a = [0u8; 81];
    a[0..32].copy_from_slice(&issuer_hash);
    a[32..40].copy_from_slice(&threshold.to_be_bytes());
    a[40] = meets;
    a[41..73].copy_from_slice(&nullifier);
    a[73..81].copy_from_slice(&period.to_be_bytes());
    Bytes::from_array(env, &a)
}

fn setup(env: &Env) -> (Address, Address, Address, BytesN<32>) {
    let admin = Address::generate(env);
    let router = Address::generate(env);
    let usdc = Address::generate(env);
    let image_id = BytesN::from_array(env, &[7u8; 32]);
    (admin, router, usdc, image_id)
}

#[test]
fn init_and_getters() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(ZkUnderwrite, ());
    let client = ZkUnderwriteClient::new(&env, &id);
    let (admin, router, usdc, image_id) = setup(&env);

    client.init(&admin, &router, &image_id, &usdc, &3000u64, &500_0000000i128);
    let borrower = Address::generate(&env);
    assert_eq!(client.credit_line(&borrower), 0);
}

#[test]
#[should_panic]
fn double_init_panics() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(ZkUnderwrite, ());
    let client = ZkUnderwriteClient::new(&env, &id);
    let (admin, router, usdc, image_id) = setup(&env);
    client.init(&admin, &router, &image_id, &usdc, &3000u64, &500_0000000i128);
    client.init(&admin, &router, &image_id, &usdc, &3000u64, &500_0000000i128);
}

#[test]
fn init_rejects_zero_credit_amount() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(ZkUnderwrite, ());
    let client = ZkUnderwriteClient::new(&env, &id);
    let (admin, router, usdc, image_id) = setup(&env);

    let result = client.try_init(&admin, &router, &image_id, &usdc, &3000u64, &0i128);
    assert!(result.is_err());
}

#[test]
fn init_rejects_zero_threshold() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(ZkUnderwrite, ());
    let client = ZkUnderwriteClient::new(&env, &id);
    let (admin, router, usdc, image_id) = setup(&env);

    let result = client.try_init(&admin, &router, &image_id, &usdc, &0u64, &500_0000000i128);
    assert!(result.is_err());
}

#[test]
fn init_rejects_all_zero_image_id() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(ZkUnderwrite, ());
    let client = ZkUnderwriteClient::new(&env, &id);
    let (admin, router, usdc, _image_id) = setup(&env);
    let zero_image_id = BytesN::from_array(&env, &[0u8; 32]);

    let result = client.try_init(&admin, &router, &zero_image_id, &usdc, &3000u64, &500_0000000i128);
    assert!(result.is_err());
}

#[test]
fn request_credit_rejects_bad_journal_length() {
    let env = Env::default();
    env.mock_all_auths();
    let token_admin = Address::generate(&env);
    let usdc = env.register_stellar_asset_contract_v2(token_admin.clone());
    let usdc_id = usdc.address();
    let router = env.register(StubRouter, ());
    let id = env.register(ZkUnderwrite, ());
    let client = ZkUnderwriteClient::new(&env, &id);
    let (admin, _r, _u, image_id) = setup(&env);
    client.init(&admin, &router, &image_id, &usdc_id, &3000u64, &500_0000000i128);

    let borrower = Address::generate(&env);
    let seal = Bytes::from_array(&env, &[0u8; 4]);
    let short_journal = Bytes::from_array(&env, &[0u8; 40]); // not 81 bytes

    let result = client.try_request_credit(&borrower, &seal, &short_journal);
    assert!(result.is_err());
}

#[test]
#[should_panic]
fn read_helpers_reject_out_of_range_offsets() {
    let env = Env::default();
    // Too short for a 32-byte read at offset 0 -> the read helper must error
    // instead of letting `journal.get(..).unwrap()` panic uncontrolled.
    let short = Bytes::from_array(&env, &[0u8; 10]);
    let _ = read_bytes32(&env, &short, OFF_ISSUER_HASH);
}

#[test]
fn register_issuer_marks_trusted() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(ZkUnderwrite, ());
    let client = ZkUnderwriteClient::new(&env, &id);
    let (admin, router, usdc, image_id) = setup(&env);
    client.init(&admin, &router, &image_id, &usdc, &3000u64, &500_0000000i128);

    let issuer_hash = BytesN::from_array(&env, &[9u8; 32]);
    client.register_issuer(&issuer_hash);
    env.as_contract(&id, || {
        assert!(env
            .storage()
            .persistent()
            .has(&DataKey::Issuer(issuer_hash.clone())));
    });
}

#[test]
fn request_credit_full_flow_and_replay_guard() {
    let env = Env::default();
    env.mock_all_auths();

    // Real test USDC token (Stellar Asset Contract) + admin to mint.
    let token_admin = Address::generate(&env);
    let usdc = env.register_stellar_asset_contract_v2(token_admin.clone());
    let usdc_id = usdc.address();
    let usdc_admin = token::StellarAssetClient::new(&env, &usdc_id);
    let usdc_token = token::TokenClient::new(&env, &usdc_id);

    // Stub router (always verifies) + the zkUnderwrite contract.
    let router = env.register(StubRouter, ());
    let id = env.register(ZkUnderwrite, ());
    let client = ZkUnderwriteClient::new(&env, &id);
    let admin = Address::generate(&env);
    let image_id = BytesN::from_array(&env, &[7u8; 32]);
    let credit = 500_0000000i128;
    client.init(&admin, &router, &image_id, &usdc_id, &3000u64, &credit);

    // Register the issuer and fund the contract treasury with real test USDC.
    let issuer_hash = [0x11u8; 32];
    client.register_issuer(&BytesN::from_array(&env, &issuer_hash));
    usdc_admin.mint(&id, &1_000_0000000i128);

    let borrower = Address::generate(&env);
    let j = journal(&env, issuer_hash, 3000, 1, [0x22u8; 32], 202506);
    let seal = Bytes::from_array(&env, &[0u8; 4]);

    let granted = client.request_credit(&borrower, &seal, &j);
    assert_eq!(granted, credit);
    assert_eq!(client.credit_line(&borrower), credit);
    assert_eq!(usdc_token.balance(&borrower), credit); // real USDC moved
    assert_eq!(usdc_token.balance(&id), 1_000_0000000i128 - credit);

    // Same nullifier again must be rejected.
    let replay = client.try_request_credit(&borrower, &seal, &j);
    assert!(replay.is_err());
}

#[test]
fn request_credit_rejects_unregistered_issuer_and_below_threshold() {
    let env = Env::default();
    env.mock_all_auths();
    let token_admin = Address::generate(&env);
    let usdc = env.register_stellar_asset_contract_v2(token_admin.clone());
    let usdc_id = usdc.address();
    token::StellarAssetClient::new(&env, &usdc_id).mint(
        &Address::generate(&env),
        &1i128,
    );
    let router = env.register(StubRouter, ());
    let id = env.register(ZkUnderwrite, ());
    let client = ZkUnderwriteClient::new(&env, &id);
    let admin = Address::generate(&env);
    client.init(
        &admin,
        &router,
        &BytesN::from_array(&env, &[7u8; 32]),
        &usdc_id,
        &3000u64,
        &500_0000000i128,
    );
    token::StellarAssetClient::new(&env, &usdc_id).mint(&id, &1_000_0000000i128);
    let borrower = Address::generate(&env);
    let seal = Bytes::from_array(&env, &[0u8; 4]);

    // Unregistered issuer -> reject.
    let j_unreg = journal(&env, [0x11u8; 32], 3000, 1, [0x22u8; 32], 202506);
    assert!(client.try_request_credit(&borrower, &seal, &j_unreg).is_err());

    // Register issuer, but income does not meet threshold -> reject.
    client.register_issuer(&BytesN::from_array(&env, &[0x11u8; 32]));
    let j_low = journal(&env, [0x11u8; 32], 3000, 0, [0x23u8; 32], 202506);
    assert!(client.try_request_credit(&borrower, &seal, &j_low).is_err());
    assert_eq!(client.credit_line(&borrower), 0);
}

#[test]
fn journal_readers_roundtrip() {
    let env = Env::default();
    // Build an 81-byte journal: issuer_hash=0x11.., threshold=3000, meets=1,
    // nullifier=0x22.., period=202506.
    let mut arr = [0u8; JOURNAL_LEN as usize];
    for b in arr[0..32].iter_mut() {
        *b = 0x11;
    }
    arr[32..40].copy_from_slice(&3000u64.to_be_bytes());
    arr[40] = 1;
    for b in arr[41..73].iter_mut() {
        *b = 0x22;
    }
    arr[73..81].copy_from_slice(&202506u64.to_be_bytes());

    let journal = Bytes::from_array(&env, &arr);
    assert_eq!(read_u64_be(&env, &journal, OFF_THRESHOLD), 3000);
    assert_eq!(journal.get(OFF_MEETS).unwrap(), 1);
    assert_eq!(read_u64_be(&env, &journal, OFF_PERIOD), 202506);
    assert_eq!(
        read_bytes32(&env, &journal, OFF_ISSUER_HASH),
        BytesN::from_array(&env, &[0x11u8; 32])
    );
    assert_eq!(
        read_bytes32(&env, &journal, OFF_NULLIFIER),
        BytesN::from_array(&env, &[0x22u8; 32])
    );
}

#[test]
fn unregister_then_reregister_issuer_works() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(ZkUnderwrite, ());
    let client = ZkUnderwriteClient::new(&env, &id);
    let (admin, router, usdc, image_id) = setup(&env);
    client.init(&admin, &router, &image_id, &usdc, &3000u64, &500_0000000i128);

    let issuer_hash = BytesN::from_array(&env, &[9u8; 32]);
    client.register_issuer(&issuer_hash);
    client.unregister_issuer(&issuer_hash);
    env.as_contract(&id, || {
        assert!(!env
            .storage()
            .persistent()
            .has(&DataKey::Issuer(issuer_hash.clone())));
    });

    // Re-registering the same issuer after revocation must work again.
    client.register_issuer(&issuer_hash);
    env.as_contract(&id, || {
        assert!(env
            .storage()
            .persistent()
            .has(&DataKey::Issuer(issuer_hash.clone())));
    });
}

#[test]
fn unregister_issuer_by_non_admin_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(ZkUnderwrite, ());
    let client = ZkUnderwriteClient::new(&env, &id);
    let (admin, router, usdc, image_id) = setup(&env);
    client.init(&admin, &router, &image_id, &usdc, &3000u64, &500_0000000i128);
    let issuer_hash = BytesN::from_array(&env, &[9u8; 32]);
    client.register_issuer(&issuer_hash);

    // An attacker authorizes this exact invocation, but the contract still
    // requires the stored admin's own authorization -> must fail.
    let attacker = Address::generate(&env);
    let result = client
        .mock_auths(&[MockAuth {
            address: &attacker,
            invoke: &MockAuthInvoke {
                contract: &id,
                fn_name: "unregister_issuer",
                args: (issuer_hash.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }])
        .try_unregister_issuer(&issuer_hash);
    assert!(result.is_err());
    env.as_contract(&id, || {
        assert!(env
            .storage()
            .persistent()
            .has(&DataKey::Issuer(issuer_hash.clone())));
    });
}

#[test]
fn propose_and_accept_admin_transfers_admin() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(ZkUnderwrite, ());
    let client = ZkUnderwriteClient::new(&env, &id);
    let (admin, router, usdc, image_id) = setup(&env);
    client.init(&admin, &router, &image_id, &usdc, &3000u64, &500_0000000i128);

    let new_admin = Address::generate(&env);
    client.propose_admin(&new_admin);
    client.accept_admin();

    env.as_contract(&id, || {
        let stored_admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        assert_eq!(stored_admin, new_admin);
        assert!(!env.storage().instance().has(&DataKey::PendingAdmin));
    });
}

#[test]
fn accept_admin_by_wrong_caller_fails() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(ZkUnderwrite, ());
    let client = ZkUnderwriteClient::new(&env, &id);
    let (admin, router, usdc, image_id) = setup(&env);
    client.init(&admin, &router, &image_id, &usdc, &3000u64, &500_0000000i128);

    let new_admin = Address::generate(&env);
    client.propose_admin(&new_admin);

    // Someone other than the proposed new admin tries to accept.
    let attacker = Address::generate(&env);
    let result = client
        .mock_auths(&[MockAuth {
            address: &attacker,
            invoke: &MockAuthInvoke {
                contract: &id,
                fn_name: "accept_admin",
                args: ().into_val(&env),
                sub_invokes: &[],
            },
        }])
        .try_accept_admin();
    assert!(result.is_err());
    env.as_contract(&id, || {
        let stored_admin: Address = env.storage().instance().get(&DataKey::Admin).unwrap();
        assert_eq!(stored_admin, admin);
    });
}

#[test]
fn cancel_admin_proposal_clears_pending_and_blocks_accept() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(ZkUnderwrite, ());
    let client = ZkUnderwriteClient::new(&env, &id);
    let (admin, router, usdc, image_id) = setup(&env);
    client.init(&admin, &router, &image_id, &usdc, &3000u64, &500_0000000i128);

    let new_admin = Address::generate(&env);
    client.propose_admin(&new_admin);
    client.cancel_admin_proposal();

    env.as_contract(&id, || {
        assert!(!env.storage().instance().has(&DataKey::PendingAdmin));
    });

    // Nothing is pending anymore, so accepting must fail.
    let result = client.try_accept_admin();
    assert!(result.is_err());
}

#[test]
fn new_admin_can_act_and_old_admin_cannot() {
    let env = Env::default();
    env.mock_all_auths();
    let id = env.register(ZkUnderwrite, ());
    let client = ZkUnderwriteClient::new(&env, &id);
    let (admin, router, usdc, image_id) = setup(&env);
    client.init(&admin, &router, &image_id, &usdc, &3000u64, &500_0000000i128);

    let new_admin = Address::generate(&env);
    client.propose_admin(&new_admin);
    client.accept_admin();

    // The new admin can now register an issuer.
    let issuer_hash = BytesN::from_array(&env, &[3u8; 32]);
    client
        .mock_auths(&[MockAuth {
            address: &new_admin,
            invoke: &MockAuthInvoke {
                contract: &id,
                fn_name: "register_issuer",
                args: (issuer_hash.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }])
        .register_issuer(&issuer_hash);
    env.as_contract(&id, || {
        assert!(env
            .storage()
            .persistent()
            .has(&DataKey::Issuer(issuer_hash.clone())));
    });

    // The old admin no longer has authority to register an issuer.
    let other_hash = BytesN::from_array(&env, &[4u8; 32]);
    let result = client
        .mock_auths(&[MockAuth {
            address: &admin,
            invoke: &MockAuthInvoke {
                contract: &id,
                fn_name: "register_issuer",
                args: (other_hash.clone(),).into_val(&env),
                sub_invokes: &[],
            },
        }])
        .try_register_issuer(&other_hash);
    assert!(result.is_err());
}
