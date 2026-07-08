#!/usr/bin/env bash
# Final step: generate a REAL Groth16 proof and claim the USDC credit line on
# Stellar testnet, against the already-deployed zkUnderwrite contract.
#
# Run after the verifier stack + contract are deployed (see DEPLOYMENTS.md) and
# the RISC Zero toolchain container `zku-toolchain` is up.
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"

NET=testnet
ZKU=$(cat .zku_contract)
USDC=$(cat .usdc_sac)
ISSUER_G=$(cat .usdc_issuer)
CTR=zku-toolchain
EXEC="docker exec -e PATH=/usr/local/cargo/bin:/root/.risc0/bin:/usr/bin:/bin -e CARGO_TARGET_DIR=/build/target -e RISC0_DEV_MODE=0 $CTR bash -c"

echo "==> 0. Borrower account + USDC trustline"
stellar keys generate zku-borrower --network $NET --fund 2>/dev/null || true
BORROWER=$(stellar keys address zku-borrower)
echo "    borrower: $BORROWER"
# A classic G-account must trust USDC:issuer to receive the SAC token.
stellar tx new change-trust --line "USDC:$ISSUER_G" --source-account zku-borrower --network $NET 2>&1 | grep -aiE "tx/|success|already" | tail -1 || true

echo "==> 1. Generate the real Groth16 proof in the container (over the real signed statement)"
$EXEC 'cd /work/zkvm && cp ../work/statement.json ../work/signature.bin ../work/issuer_pubkey.bin . && THRESHOLD=3000 PERIOD=202506 cargo run --release -q -p host'
SEAL=$($EXEC 'sed -n 1p /work/zkvm/proof.txt' | tr -d "\r\n")
IMG=$($EXEC 'sed -n 2p /work/zkvm/proof.txt' | tr -d "\r\n")
JOURNAL=$($EXEC 'sed -n 4p /work/zkvm/proof.txt' | tr -d "\r\n")
echo "    image_id : $IMG"
echo "    journal  : $JOURNAL"
echo "    seal     : ${SEAL:0:40}… (${#SEAL} hex chars)"

echo "==> 2. credit line BEFORE"
stellar contract invoke --send=no --source-account zku-deployer --network $NET --id "$ZKU" -- \
    credit_line --borrower "$BORROWER" 2>/dev/null | tail -1

echo "==> 3. request_credit (contract verifies the proof on-chain, then disburses USDC)"
stellar contract invoke --source-account zku-borrower --network $NET --id "$ZKU" -- \
    request_credit --borrower "$BORROWER" --seal "$SEAL" --journal "$JOURNAL" 2>&1 \
    | grep -aiE "tx/|error|fail|[0-9]{6,}" | tail -3

echo "==> 4. credit line AFTER + borrower USDC balance"
stellar contract invoke --send=no --source-account zku-deployer --network $NET --id "$ZKU" -- \
    credit_line --borrower "$BORROWER" 2>/dev/null | tail -1
stellar contract invoke --send=no --source-account zku-deployer --network $NET --id "$USDC" -- \
    balance --id "$BORROWER" 2>/dev/null | tail -1

echo "✅ Done. The chain verified a Groth16 proof of income and unlocked a USDC credit line —"
echo "   without ever seeing the borrower's transactions or identity."
