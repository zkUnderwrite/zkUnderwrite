# zkUnderwrite — Testnet Deployments

Network: **Stellar Testnet** (Protocol 27). Deployer identity: `zku-deployer`
= `GA5TVGKVXW4CVFLPQXKKKGPH63VT6FKB4LKMTPRIBLPCMYMOO2GYQIZX`.

## RISC Zero verifier stack (forked NethermindEth/stellar-risc0-verifier)

| Contract | Address |
|---|---|
| TimelockController | `CBKU7MT3MFYSVFVPPMTW3G364BIT7LJFTQHKFKI6EZV7A2YGJFRBLY3L` |
| VerifierRouter | `CB2K2RS7CAY6AUZWWX5VI6SS5ZVSC5XYAN5ZCNG2FAZMAOHCSOYZ3S3T` |
| Groth16Verifier | `CCGTCTDQI7YU2YBWXZPERJZCLFZ5ZSVW6JVEYEGWC4XKQRZNYDZPTIEV` |
| EmergencyStop (routed target) | `CCAG5V7HGSPLV47C4NA5D57TCXAB6S43JOALXEZ7DQBR72QBLAQVLBPE` |

- Selector: `73c457ba` — Version `3.0.0` — registered & routable
  (`get_verifier_by_selector(73c457ba)` → EmergencyStop address).
- min-delay: 0s (testnet).

### Known cosmetic issue
Stellar CLI 25.2.0 panics *after* successful submission when displaying a
returned `Bytes` value (`soroban-spec-tools/src/lib.rs:593: not yet implemented:
Bytes(...) doesn't have a matching Val`). The schedule/execute transactions
**succeed on-chain** regardless. Contract-to-contract `verify()` returns `()`
and is unaffected. (Upgrade CLI if a clean CLI-side `verify` display is needed.)

## zkUnderwrite application contract
- **Contract:** `CCLXJCWPJ6FDTDITRAHCPHCD55LYXUCEYYLER5UKKCIS5UUEPP2DACBB`
- init tx `a62804de74a2d88c23c52a6d52c40f26ab30e6ff993c001890a4de6a377f7ced`
- register_issuer tx `94d2204cc7420ac21f0ea443b283b8e7ed54c27f7732607e740123bfb288c88a`
- Policy: required_threshold=3000, credit_amount=500_0000000 (500 USDC)

## Real testnet USDC (for credit disbursement)
- **USDC SAC:** `CDDHQYZQBR3347KAMZFB52ISBSNNDXJMSMPVBYQ2FTHH7KBIIMZZYTO6`
- USDC issuer account: `GDIK337PHXULA7NIAH2PYFEKXXLV2EMODWS5LUDREY6YST3LH3TZMEZB`
- Treasury funded: 10,000 USDC minted to the contract (mint tx `7a6b2835b24eec1dcd4bec35ab2df5c24dcc2933410d32b8f81fddd138ca37aa`)

## Guest / issuer
- Issuer demo pubkey hash (registered): `333187b7b6e2f1ab0c94fd1f0645081aefd9b72e303554e83017f18958b203bf`
- **Guest image id:** `7757f5c3ee02c11ea21487236ad0982480182d4e77220e1013e85772592ffece`
- Guest logic validated end-to-end (dev-mode execution over real signed data): journal = {issuer_hash, threshold=3000, meets=1, nullifier, period=202506}.

## Remaining: one real Groth16 proof → request_credit
- Local Groth16 (stark2snark) needs ~7-8GB RAM; Docker VM is 7.65GB with ~2GB used by other dev stacks. One-time step; pending user's choice on RAM (bump Docker to 16GB, or briefly pause other containers, or Bonsai).
