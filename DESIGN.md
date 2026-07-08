# zkUnderwrite — Technical Design

A privacy-preserving creditworthiness oracle on Stellar. A borrower proves their
bank/payroll-attested income meets a lender's threshold — without revealing any
transaction or their identity — and that proof unlocks an undercollateralized
USDC credit line on Stellar testnet.

## Trust & soundness model

1. **Issuer authenticity (oracle fix):** income data is Ed25519-signed by a
   registered *issuer* (a bank/payroll provider). The signature is verified
   **inside the RISC Zero guest**, so a borrower cannot fabricate income — the
   proof only exists if real issuer-signed data was used.
2. **Program authenticity (image-ID binding):** the `zkUnderwrite` contract
   stores the **expected guest image ID** and passes *that* to the verifier
   (never a caller-supplied one). Otherwise a borrower could run a different
   program that always returns `true`.
3. **Output integrity:** the contract receives raw `journal_bytes`, computes
   `sha256(journal_bytes)` itself, passes it to `verify(...)`, and only then
   parses those same bytes. The values it acts on are exactly the proven ones.
4. **Replay/Sybil resistance:** the journal carries a `nullifier`; the contract
   rejects a reused nullifier.

What is real (no mocks): Ed25519 signatures, the RISC Zero proof, the Soroban
contracts, and the testnet USDC transfer. Only the *issuer role* is played by us
in the demo (a real keypair seeded into the on-chain issuer registry) — exactly
how Plaid/payroll APIs are the trust root in production.

## Signed income statement (issuer → borrower)

The issuer signs the **exact UTF-8 bytes** of a canonical JSON document; the
guest receives those exact bytes plus the signature, so no re-serialization /
canonicalization ambiguity arises.

```json
{
  "schema": "zku.income.v1",
  "subject_id": "acct_4f9c2a17",
  "issuer": "bank-of-stellar",
  "currency": "USD",
  "issued_at": 1750550400,
  "period_months": 3,
  "monthly_net_income": [4200, 4250, 4180]
}
```

- `subject_id`: opaque, issuer-scoped account id → feeds the nullifier (never revealed on-chain).
- `monthly_net_income`: last N months net income, whole currency units.

## Guest program (off-chain, RISC Zero, Rust)

Private input: `statement_bytes`, `signature[64]`, `issuer_pubkey[32]`.
Public params (also committed): `threshold: u64`, `period: u64`.

Steps:
1. `ed25519_dalek::verify(issuer_pubkey, statement_bytes, signature)` → panic on failure (no proof).
2. Parse `statement_bytes` (serde_json) → fields.
3. `avg = sum(monthly_net_income) / period_months`; `recurring = all months > 0`.
4. `income_meets_threshold = recurring && avg >= threshold`.
5. `nullifier = sha256(subject_id || "|" || issuer || "|" || period_le)`.
6. `issuer_pubkey_hash = sha256(issuer_pubkey)`.
7. Commit the **journal** (fixed 81-byte layout below). No raw amounts leave the device.

## Journal byte layout (89 → 81 bytes, big-endian, fixed)

| Offset | Len | Field                  | Notes                                  |
|--------|-----|------------------------|----------------------------------------|
| 0      | 32  | `issuer_pubkey_hash`   | contract checks against issuer registry|
| 32     | 8   | `threshold` (u64 BE)   | the income threshold that was proven   |
| 40     | 1   | `income_meets_threshold` | 0 / 1                                |
| 41     | 32  | `nullifier`            | sha256; replay/Sybil guard             |
| 73     | 8   | `period` (u64 BE)      | e.g. yyyymm; scopes the nullifier      |

Total: **81 bytes.** Only a boolean is revealed about the income — never the
amount. (`journal_digest = sha256(these 81 bytes)`.)

## `zkUnderwrite` Soroban contract

Storage: `admin`, `router` (risc0 verifier router address), `expected_image_id:
BytesN<32>`, `usdc: Address` (real testnet USDC SAC), `required_threshold: u64`,
`credit_amount: i128`, `issuers: Map<BytesN<32>, ()>`, `nullifiers:
Map<BytesN<32>, ()>`, `credit_lines: Map<Address, i128>`.

Functions:
- `init(admin, router, expected_image_id, usdc, required_threshold, credit_amount)`
- `register_issuer(issuer_pubkey_hash)` — admin auth.
- `request_credit(borrower: Address, seal: Bytes, journal_bytes: Bytes)`:
  1. `borrower.require_auth()`
  2. `digest = env.crypto().sha256(journal_bytes)`
  3. `RiscZeroVerifierRouterClient::new(env, router).verify(&seal, &expected_image_id, &digest)` — reverts on invalid proof.
  4. Parse `journal_bytes` → `(issuer_hash, threshold, meets, nullifier, period)`.
  5. Require `issuers.contains(issuer_hash)`.
  6. Require `threshold >= required_threshold` and `meets == 1`.
  7. Require `!nullifiers.contains(nullifier)`; insert it.
  8. Set `credit_lines[borrower] = credit_amount`; transfer `credit_amount` of
     real testnet USDC from the contract treasury to `borrower` (TokenClient).
  9. Emit `CreditGranted(borrower, credit_amount, period)`.

## Components & layout

```
zkunderwrite/
  Dockerfile.risc0        # linux/amd64 RISC Zero 3.0.0 build/prove env (Intel-Mac fix)
  reference-verifier/     # forked NethermindEth/stellar-risc0-verifier
  methods/                # RISC Zero guest (income proof) + build
  host/                   # borrower CLI: build proof.txt (seal,image_id,journal)
  issuer/                 # issuer service: Ed25519 sign income statements (real key)
  contracts/zkunderwrite/ # Soroban application contract
  app/                    # minimal lender dashboard (reads contract state)
```

## Open verification items (Day 1 gate)

- Confirm RISC Zero 3.0.0 proof verifies against the deployed verifier (control-root match).
- Confirm `soroban-sdk 25.1.0` verifier builds & deploys against testnet (Protocol 27).
- Measure real proving time, Groth16 seal size, and on-chain verify tx cost.
