# zkUnderwrite — prove your income, not your bank statements

**A privacy-preserving creditworthiness oracle on Stellar.** A borrower proves
that their bank/payroll-attested income meets a lender's threshold — revealing
**no transactions and no identity** — and a Soroban smart contract verifies the
proof and unlocks an undercollateralized **USDC credit line** on Stellar.

> *Plaid/Argyle, but zero-knowledge.* The missing private bridge between
> real-world income data and on-chain credit.

Built for **Stellar Hacks: Real-World ZK**. Everything below runs on **Stellar
testnet** with **real** Ed25519 signatures, **real** RISC Zero Groth16 proofs,
and **real** USDC movement — no mock data.

---

## The problem

On-chain lending is almost entirely *over*-collateralized, because a lender has
no private way to assess a borrower's real-world income. Off-chain, income
verification (Plaid, Argyle, Truv) is a multi-billion-dollar industry — but it
works by handing your full bank history to every party that asks, leaking PII at
every step.

zkUnderwrite breaks that trade-off: the borrower proves *the one fact the lender
needs* ("my income clears your bar") and nothing else.

## Why the ZK is load-bearing

ZK is not a feature here — it is the entire trust model. Remove it and the only
way to prove income is to disclose the statements. The Groth16 proof, verified
on-chain, is the *sole* thing that unlocks credit. It carries:

- a guarantee the income data was **signed by a registered issuer** (verified
  *inside* the zkVM),
- a guarantee that **income ≥ threshold** over a real period,
- a **nullifier** for Sybil/replay resistance,

…while the amounts, transactions, and the borrower's identity never leave the
device.

## How it works

```
  ┌─────────────┐   signs income     ┌────────────────────────┐
  │   Issuer    │  statement (Ed25519)│  Borrower's device     │
  │ bank/payroll│ ──────────────────► │  RISC Zero zkVM guest  │
  └─────────────┘                     │  • verify signature    │
                                      │  • avg income ≥ thresh │
                                      │  • compute nullifier   │
                                      │  → Groth16 receipt     │
                                      └───────────┬────────────┘
                                                  │ seal + journal
                                                  ▼
  ┌───────────────────────────────────────────────────────────┐
  │  Stellar (Soroban)                                         │
  │  zkUnderwrite ──verify(seal, OUR image_id, journal)──►     │
  │      │                         RISC Zero Groth16 verifier  │
  │      │ checks: issuer registered · threshold · meets ·     │
  │      │         nullifier unused                            │
  │      └──► transfers USDC credit line to the borrower       │
  └───────────────────────────────────────────────────────────┘
```

1. **Issuer signs** an income statement with an Ed25519 key (a bank/payroll
   provider's role). In the demo we operate this key; in production the contract's
   issuer registry holds real institutions' keys.
2. **Borrower proves**, on their own device, inside a RISC Zero zkVM: the guest
   verifies the issuer's signature over the exact statement, computes average
   monthly income and recurrence, and commits an 81-byte journal.
3. **Contract verifies** the Groth16 proof against the *exact* guest program it
   expects, then enforces lender policy.
4. **Credit unlocks**: real testnet USDC is disbursed; the nullifier is recorded.

## Soundness model

ZK proofs are only as good as what binds them. zkUnderwrite closes the usual gaps:

- **Program binding (the critical one).** The verifier's `verify(seal, image_id,
  journal)` trusts the *caller-supplied* `image_id`. So the `zkUnderwrite`
  contract stores the **expected guest image id** and passes *that* — never a
  value from the transaction. A borrower cannot substitute a different program
  that always returns `true`.
- **Output integrity.** The contract receives the raw `journal_bytes`, computes
  `sha256` itself, passes that to the verifier, and only then parses the same
  bytes. The values it acts on are exactly the ones proven.
- **Input authenticity (the oracle problem).** A proof shows a computation ran
  over *some* input, not that the input is real. We resolve this by verifying the
  **issuer's Ed25519 signature inside the guest** — the proof only exists if the
  data was genuinely issuer-signed.
- **Sybil / replay.** The journal carries a `nullifier = sha256(subject | issuer
  | period)`; the contract rejects any reuse.

## The journal (81 bytes, what the chain sees)

| Offset | Len | Field | Note |
|---|---|---|---|
| 0 | 32 | `issuer_pubkey_hash` | checked against the issuer registry |
| 32 | 8 | `threshold` (u64 BE) | the bar that was proven |
| 40 | 1 | `income_meets_threshold` | `0` / `1` — **the only thing revealed about income** |
| 41 | 32 | `nullifier` | replay/Sybil guard |
| 73 | 8 | `period` (u64 BE) | scopes the nullifier |

The exact income is **never** committed — only the boolean.

## Deployed on Stellar testnet

| Contract | ID |
|---|---|
| **zkUnderwrite** | `CCLXJCWPJ6FDTDITRAHCPHCD55LYXUCEYYLER5UKKCIS5UUEPP2DACBB` |
| RISC Zero router | `CB2K2RS7CAY6AUZWWX5VI6SS5ZVSC5XYAN5ZCNG2FAZMAOHCSOYZ3S3T` |
| Groth16 verifier | `CCGTCTDQI7YU2YBWXZPERJZCLFZ5ZSVW6JVEYEGWC4XKQRZNYDZPTIEV` |
| USDC (testnet SAC) | `CDDHQYZQBR3347KAMZFB52ISBSNNDXJMSMPVBYQ2FTHH7KBIIMZZYTO6` |

- Guest image id: `7757f5c3ee02c11ea21487236ad0982480182d4e77220e1013e85772592ffece`
- RISC Zero **3.0.5** (Groth16 / BN254); verifier forked from
  [NethermindEth/stellar-risc0-verifier](https://github.com/NethermindEth/stellar-risc0-verifier).
- Full address list and txids in [`DEPLOYMENTS.md`](DEPLOYMENTS.md).

## Repository layout

```
zkunderwrite/
  zkvm/                  RISC Zero project
    methods/guest/       guest: Ed25519 verify + income logic + nullifier
    host/                borrower CLI: produces the Groth16 receipt + journal
  contracts/zkunderwrite/  Soroban app contract (verify → disburse USDC)
  reference-verifier/    forked Nethermind RISC Zero Groth16 verifier
  issuer/                issuer service: signs income statements (Ed25519)
  app/                   lender dashboard (live testnet reads)
  scripts/e2e.sh         full end-to-end run
  Dockerfile.risc0       linux/amd64 RISC Zero 3.0.5 build/prove environment
  DESIGN.md  DEPLOYMENTS.md
```

## Running it

**Build/prove environment.** The RISC Zero toolchain (`rzup`) ships no Intel-macOS
binary, so all guest builds + proving run in a `linux/amd64` container (native on
Intel, no emulation). Stellar work runs natively.

```bash
docker build --platform linux/amd64 -f Dockerfile.risc0 -t zku-risc0 .
```

**Issuer signs a statement (real Ed25519):**
```bash
cd issuer && cargo run -- keygen        # prints issuer_pubkey_hash
cargo run -- sign acct_4f9c2a17 bank-of-stellar 4200 4250 4180
```

**Generate a proof + run end-to-end on testnet:**
```bash
./scripts/e2e.sh    # build guest → prove → deploy → verify on-chain → unlock USDC
```

**Lender dashboard** (live reads of the deployed contract):
```bash
cd app && python3 -m http.server 8731   # open http://localhost:8731
```

## Tech stack

- **ZK:** RISC Zero zkVM 3.0.5, Groth16 over BN254.
- **Chain:** Stellar / Soroban (Protocol 26+ BN254 host functions), `soroban-sdk` 25.
- **Crypto in-guest:** Ed25519 signature verification, SHA-256.
- **Token:** real testnet USDC via a Stellar Asset Contract.

## Honest limitations

- **Trusted issuer (by design, demo-scoped).** The issuer registry is the trust
  root — exactly like Plaid/payroll APIs today. In the demo we operate the issuer
  key; production onboards real institutions, or removes the trusted party
  entirely with zkTLS (TLSNotary/Reclaim) attesting a bank API response inside the
  guest.
- **Verifier not audited.** The forked RISC Zero verifier is a reference
  implementation; testnet only, no real funds.
- **Local Groth16 proving is memory-heavy** (~8 GB). On constrained machines, use
  RISC Zero's Bonsai remote prover; the on-chain verification is identical either
  way.
- **Recipient binding (planned).** This version's proof is not yet bound to the
  borrower's Stellar address, so a submitted proof could be front-run by another
  caller (the nullifier then blocks the original borrower — griefing, not theft of
  the borrower's funds). The fix is to commit the recipient address into the
  journal and have the contract require `caller == journal.recipient`; it lands in
  the next guest revision.
- Single threshold / fixed credit amount per lender policy in this version;
  tiered limits are straightforward follow-ups.
