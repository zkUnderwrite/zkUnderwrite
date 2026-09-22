# Threat model

This document records the trust assumptions and known risks in zkUnderwrite as
implemented today. It complements the [Soundness model](README.md#soundness-model)
section of the README, which explains how the ZK proof binds the guest program,
the journal, and the issuer's signature. Here we go one level further: who has
to be trusted, what each actor can and cannot do, and where the current
implementation still has open gaps.

Each threat below lists: description, current mitigation (only what is
actually implemented in this repository today), residual risk, and whether a
future issue may address it. No issue numbers are invented; where an open
issue in this repository already covers part of a gap, it is named.

## Actors

- **Issuer.** Holds an Ed25519 signing key (`issuer/src/main.rs`) and signs
  income statements (`subject_id`, `issuer`, `period`, `period_months`,
  `monthly_net_income`, ...). Plays the role of a bank or payroll provider.
  The contract trusts an issuer purely by `sha256(issuer_pubkey)` being
  present in its `Issuer(...)` storage map (`register_issuer` in
  `contracts/zkunderwrite/src/lib.rs`).
- **Borrower / prover.** Runs the RISC Zero guest
  (`zkvm/methods/guest/src/main.rs`) locally via the host
  (`zkvm/host/src/main.rs`). Supplies `statement.json`, `signature.bin`,
  `issuer_pubkey.bin`, and two host-side values that are *not* part of the
  signed statement: `THRESHOLD` and `PERIOD` (both read from environment
  variables in `zkvm/host/src/main.rs`, defaulted if unset). Submits the
  resulting seal and journal to `request_credit`.
- **Admin.** The address that called `init` on the contract. Can call
  `register_issuer` (`admin.require_auth()`). There is currently no
  `unregister_issuer` and no admin-transfer function in
  `contracts/zkunderwrite/src/lib.rs` — the admin set at `init` is permanent
  for the life of the contract.
- **Treasury.** The contract's own token balance of the `usdc` Stellar Asset
  Contract configured at `init`. `request_credit` transfers directly from
  `env.current_contract_address()` to the borrower
  (`token::TokenClient::new(&env, &usdc).transfer(...)`). There is no
  separate treasury contract or multisig; funding and disbursement both go
  through this one balance.
- **Verifier router.** The RISC Zero verifier router contract address stored
  at `init` (`DataKey::Router`). `request_credit` calls
  `RiscZeroVerifierRouterClient::new(&env, &router).verify(seal, image_id,
  journal_digest)`. The contract trusts whatever router address the admin
  configured; it does not pin or validate the router's own code.

## Trust in issuers

**Description.** The guest verifies that the statement bytes were signed by
the Ed25519 key in `issuer_pubkey.bin`, and the contract checks that
`sha256(issuer_pubkey)` is in its registry. Neither the guest nor the
contract checks anything about *who* controls that key or whether the income
figures inside the statement are true. An issuer key, once registered, can
sign a statement for any `subject_id` with any `monthly_net_income` values —
there is no on-chain KYC, no attestation of the issuer's real-world identity,
and no way for the contract to distinguish a legitimate bank from a
registered key that has been compromised or is run by a colluding party.

**Current mitigation.** Only `admin.require_auth()`-gated `register_issuer`
calls add an issuer; an attacker who does not control the admin key cannot
add their own issuer. The guest does enforce that the statement was signed
by *a* registered key's corresponding private key, which is what makes the
proof "issuer-attested" rather than borrower-asserted.

**Residual risk.** The trust root is entirely the admin's judgment in
registering an issuer key, plus that issuer's operational security. A
malicious or careless issuer (or a leaked issuer signing key) can mint
statements that pass every check in the guest and the contract, unlocking
real USDC credit for fabricated income. This is a policy/off-chain-vetting
problem, not something the current proof system can rule out.

**Follow-up.** Any stronger issuer accountability (e.g. bonding, revocation,
multi-issuer corroboration) would be a future issue; none exists today.

## Borrower-chosen `threshold`; issuer-signed `period`

**Description.** `threshold` is written by the **host** into the guest's
`env::read()` input (`zkvm/host/src/main.rs`), not read from the signed
`statement.json`. It is compared against the contract's `RequiredThreshold`
policy (`request_credit` rejects `threshold < required`), so a borrower
cannot claim a lower bar than the lender requires — but the borrower still
picks the exact `threshold` value that is committed into the journal and can
set it to exactly the lender's minimum regardless of their real income
margin above it. That part is intended: the journal is only supposed to
reveal "income meets threshold", not the amount.

`period` used to have the same shape of problem and has been fixed
(`fix(zk): bind period and nullifier to signed statement data`, issue #11):
`period` is now a field on the signed `Statement` (`issuer/src/main.rs`,
`zkvm/methods/guest/src/main.rs`) and the guest reads it from the parsed,
signature-verified statement (`st.period`) instead of accepting it as a host
`env::read()` input. `zkvm/host/src/main.rs` no longer writes a `PERIOD`
value into the executor environment at all. Because `period` is now covered
by the issuer's Ed25519 signature over `statement_bytes`, a borrower can no
longer re-run the prover against the same signed statement with a different
period to mint a fresh nullifier — the period, and therefore the nullifier,
is fixed the moment the issuer signs.

**Current mitigation.** `period` is part of the signed statement and is
folded into the nullifier alongside `subject_id`/`issuer` (see the next
section for the encoding). The guest has no code path that reads a period
value from the host.

**Residual risk.** None from host-supplied period variation. The remaining
exposure is the same as for any signed field: a borrower can only obtain
distinct valid `(subject_id, issuer, period)` nullifiers by obtaining
distinct issuer-signed statements, which requires issuer cooperation and is
the intended trust boundary (see "Issuer authenticity and trust" above).

**Follow-up.** None outstanding for this specific weakness; issue #11 is
resolved by this change.

## Nullifier scope and the `|`-join non-injectivity

**Description.** The nullifier used to be computed as
`sha256(subject_id.as_bytes() || b"|" || issuer.as_bytes() || b"|" ||
period.to_le_bytes())` (`zkvm/methods/guest/src/main.rs`). Both `subject_id`
and `issuer` are attacker-controlled strings inside the signed statement (the
issuer signs whatever the borrower or issuer-service operator put in those
fields at signing time — see `issuer/src/main.rs`, `sign()`). Concatenating
two variable-length strings with a single `|` byte as separator is not
injective: `subject_id = "a|b"`, `issuer = "c"` produces the exact same
pre-image bytes as `subject_id = "a"`, `issuer = "b|c"`, for the same
`period`. If any legitimate `subject_id` or `issuer` value could contain the
literal `|` character, two different logical (subject, issuer) pairs could
collide on the same nullifier, or conversely a party could deliberately
choose a `subject_id` containing `|` to make their nullifier collide with an
existing one (denial of service against themselves) or, more relevant, to
make two conceptually different statements delimit identically and be
treated as the same nullifier scope.

This has been fixed (issue #11): the nullifier is now computed as
`sha256(len(subject_id) as u32 BE || subject_id || len(issuer) as u32 BE ||
issuer || period as u64 BE)`. Each variable-length field is preceded by its
own fixed-width big-endian length prefix, so no byte sequence can be
reinterpreted as belonging to a different field — the encoding is injective
regardless of what bytes `subject_id` or `issuer` contain. `period` is now
also big-endian in the nullifier hash (previously little-endian), matching
the journal's encoding of the same value.

**Current mitigation.** Length-prefixed encoding in
`zkvm/methods/guest/src/main.rs` (see above).

**Residual risk.** None from the join ambiguity described above. Two
distinct `(subject_id, issuer, period)` triples can no longer produce a
colliding pre-image.

**Follow-up.** None outstanding for this specific weakness; issue #11 is
resolved by this change.

## Treasury drain scenarios

**Description.** `request_credit` transfers a **fixed** `CreditAmount` (set
once at `init`, no per-request sizing) straight from the contract's own USDC
balance to any `borrower` address that supplies a valid proof satisfying
policy. There is no rate limiting, no per-borrower cap beyond the implicit
one-nullifier-per-(subject, issuer, period) rule (see below), and no circuit
breaker.

**Current mitigation.**
- Proof validity (Groth16 verification against the pinned `image_id`) means a
  borrower cannot forge an income claim without a genuine issuer signature.
- `IssuerNotRegistered`, `ThresholdTooLow`, `IncomeBelowThreshold`, and
  `NullifierAlreadyUsed` checks in `request_credit` gate disbursement.
- Each successful, distinct nullifier can only disburse once.

**Residual risk.** The `period`-binding weakness that used to let one signed
income statement be turned into multiple accepted nullifiers (and therefore
multiple `CreditAmount` disbursements) is fixed (issue #11): `period` is now
part of the issuer-signed statement, so a compromised or malicious issuer key
can still back multiple disbursements, but only by signing multiple distinct
statements — not by a borrower varying a host-supplied value against one
signed statement. There is still no contract-level cap on total disbursed
amount or remaining treasury balance check before transfer; if the treasury
balance is insufficient the SAC transfer will simply fail, but nothing in the
contract proactively pauses new credit lines as the balance runs low.

**Follow-up.** The `period`-binding amplification vector is closed by issue
#11; broader treasury safeguards (caps, pausability) are not tracked by an
existing issue in this repository and would need a future issue.

## Proof malleability (Groth16 / RISC0 setup as used)

**Description.** The host calls `prover.prove_with_opts(exec_env,
ZKU_GUEST_ELF, &opts)` with `ProverOpts::groth16()`
(`zkvm/host/src/main.rs`), producing a Groth16 receipt that is locally
verified (`receipt.verify(ZKU_GUEST_ID)`) before being encoded with
`risc0_ethereum_contracts::encode_seal` and submitted on-chain. On-chain, the
contract calls the RISC Zero verifier router's `verify(seal, image_id,
journal_digest)`, which performs the actual Groth16 pairing check.

**Current mitigation.** The contract never trusts a caller-supplied
`image_id` (it always uses the one stored at `init`), and it computes
`journal_digest` itself via `env.crypto().sha256(&journal)` rather than
accepting a caller-supplied digest — both documented in the README's
soundness section and confirmed in `contracts/zkunderwrite/src/lib.rs`. This
closes the two most common ways to defeat a Groth16-based verifier
(substituting the program or the statement being checked). Classic Groth16
signature malleability (re-randomizing a valid proof's group elements to
produce a second, still-valid encoding of the *same* seal/journal pair) does
not let an attacker forge a *new* statement — at most it could produce an
alternate valid encoding of an already-valid proof, which would still verify
against the same journal and the same nullifier, and would therefore still
be rejected by the `NullifierAlreadyUsed` check on any resubmission.

**Residual risk.** This repository does not vendor or audit the pairing
implementation itself — `reference-verifier/` is an already-forked
third-party verifier stack (from NethermindEth/stellar-risc0-verifier, per
the README) rather than code written for this project, and its correctness
is out of scope for zkUnderwrite's own review. Any Groth16 setup also
depends on the RISC Zero trusted setup being sound; this project does not
run or audit that setup itself, it consumes RISC Zero 3.0.5 as a dependency.
No contract-level protection against seal malleability beyond the nullifier
check described above exists today.

**Follow-up.** Auditing or replacing the vendored verifier is out of scope
for this document; no specific follow-up issue exists for it in this
repository today.

## TTL / storage expiry behavior

**Description.** `register_issuer` and the nullifier check both write to
`env.storage().persistent()` (`DataKey::Issuer(...)`, `DataKey::Nullifier(...)`
in `contracts/zkunderwrite/src/lib.rs`). Soroban persistent storage entries
are subject to state-expiration (TTL) rules on the underlying network:
entries must periodically have their TTL extended (bumped) or they can be
archived. Nothing in `contracts/zkunderwrite/src/lib.rs` currently calls any
TTL-extension API (e.g. `extend_ttl`) on issuer or nullifier entries.

**Current mitigation.** None implemented in this contract. This is not a
theoretical gap — it is already tracked by an open issue in this repository:
`fix(contract): extend storage TTLs for issuers and nullifiers` (issue #5,
open). This document describes current behavior only; it does not claim the
TTL issue is fixed.

**Residual risk.** Without TTL extension, a registered issuer's entry or a
recorded nullifier's entry could become archived over time on a live
network, requiring restoration before being read/written again, and in the
worst case (if a nullifier entry expires and is not correctly restored
before a duplicate submission) could affect whether the "already used"
guard is reliably enforced long after the original disbursement. The exact
operational impact depends on Soroban's archival/restoration semantics at
the network's current protocol version, which is outside this document's
scope to fully characterize.

**Follow-up.** Tracked by the open issue named above; a future issue.

## Key management for the issuer's Ed25519 signing key

**Description.** `zku-issuer keygen` (`issuer/src/main.rs`) generates an
Ed25519 keypair with `rand::rngs::OsRng` and writes the secret key directly
to a plaintext file, `issuer_signing.bin`, in the current working directory,
with no passphrase, no encryption at rest, and no OS keychain integration.
`zku-issuer sign` reads that file back with `fs::read(...).expect("run
keygen first")` and holds the key in process memory for the duration of the
signing operation.

**Current mitigation.** None beyond normal filesystem permissions, which
this tool does not itself set (the file is created with whatever default
mode `fs::write` produces, not explicitly hardened). This mirrors the
existing open issue `feat(issuer): harden the CLI (clap, typed errors, key
permissions, issued-at flag)` (issue #8, open), which specifically calls out
key permissions as unaddressed.

**Residual risk.** Anyone with filesystem access to wherever
`issuer_signing.bin` is stored (or a backup, or a compromised host) can sign
arbitrary income statements as that issuer, with all the consequences
described under "Trust in issuers" above. There is no key rotation
mechanism; rotating a compromised issuer key requires the admin to register
a new key, but nothing in the contract revokes the old one today
(`register_issuer` only adds, and there is no `unregister_issuer` in the
current contract) — that gap is already tracked by an open issue,
`feat(contract): add unregister_issuer, two-step set_admin and admin events`
(issue #6, open).

**Follow-up.** Partially tracked by the two open issues named above: CLI
key-permission hardening (issue #8) and issuer revocation via
`unregister_issuer` (issue #6). Neither is merged yet; this document
describes current behavior only.
