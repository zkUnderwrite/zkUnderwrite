#!/usr/bin/env bash
# zkUnderwrite end-to-end on Stellar testnet (real proofs, real token, no mocks).
#
# Prereqs:
#   - RISC Zero "full" image built: zku-risc0:latest (toolchain + risc0-groth16)
#   - Verifier stack already deployed (see DEPLOYMENTS.md)
#   - stellar CLI identity `zku-deployer` funded
#
# Run from repo root: zkunderwrite/
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"

NET=testnet
DEPLOYER=zku-deployer
ROUTER=CB2K2RS7CAY6AUZWWX5VI6SS5ZVSC5XYAN5ZCNG2FAZMAOHCSOYZ3S3T   # router (verify entrypoint)
THRESHOLD=3000
CREDIT_AMOUNT=5000000000   # 500 USDC at 7 decimals (500_0000000)

# Run guest builds / proving inside the linux/amd64 RISC Zero container.
dockr() { docker run --rm --platform linux/amd64 -v "$ROOT":/work -w /work zku-risc0:latest bash -lc "$*"; }

echo "==> 1. Build guest + host, capture the guest IMAGE ID"
dockr "cd zkvm && cargo build --release -p host 2>&1 | tail -3"
# image id printed by a tiny helper (or parse from methods). We print it from host on demand:
IMAGE_ID=$(dockr "cd zkvm && cargo run --release -q -p host -- --print-image-id" | tr -d '\r\n ')
echo "    IMAGE_ID=$IMAGE_ID"

echo "==> 2. Create a real testnet USDC asset + Stellar Asset Contract (SAC)"
stellar keys generate zku-usdc-issuer --network $NET --fund 2>/dev/null || true
ISSUER_G=$(stellar keys address zku-usdc-issuer)
USDC_SAC=$(stellar contract asset deploy --asset "USDC:$ISSUER_G" --source $DEPLOYER --network $NET 2>/dev/null \
            || stellar contract id asset --asset "USDC:$ISSUER_G" --network $NET)
echo "    USDC_SAC=$USDC_SAC (issuer $ISSUER_G)"

echo "==> 3. Deploy + init the zkUnderwrite contract"
ADMIN_G=$(stellar keys address $DEPLOYER)
ZKU=$(stellar contract deploy \
        --wasm contracts/zkunderwrite/target/wasm32v1-none/release/zkunderwrite.wasm \
        --source $DEPLOYER --network $NET)
echo "    ZKU=$ZKU"
stellar contract invoke --source $DEPLOYER --network $NET --id "$ZKU" -- init \
    --admin "$ADMIN_G" --router "$ROUTER" --expected_image_id "$IMAGE_ID" \
    --usdc "$USDC_SAC" --required_threshold $THRESHOLD --credit_amount $CREDIT_AMOUNT

echo "==> 4. Register the issuer (sha256 of issuer pubkey) + fund the contract treasury with USDC"
ISSUER_HASH=$(cat work/issuer_pubkey.bin | shasum -a 256 | awk '{print $1}')
stellar contract invoke --source $DEPLOYER --network $NET --id "$ZKU" -- \
    register_issuer --issuer_pubkey_hash "$ISSUER_HASH"
# Mint real USDC to the contract treasury (issuer is SAC admin).
stellar contract invoke --source zku-usdc-issuer --network $NET --id "$USDC_SAC" -- \
    mint --to "$ZKU" --amount 100000000000   # 10,000 USDC

echo "==> 5. Borrower generates a real Groth16 proof over the signed statement"
dockr "cd zkvm && cp ../work/statement.json ../work/signature.bin ../work/issuer_pubkey.bin . && \
       THRESHOLD=$THRESHOLD PERIOD=202506 cargo run --release -q -p host"
SEAL=$(dockr "sed -n '1p' zkvm/proof.txt" | tr -d '\r\n')
JOURNAL=$(dockr "sed -n '4p' zkvm/proof.txt" | tr -d '\r\n')

echo "==> 6. Borrower requests credit (contract verifies proof on-chain, disburses USDC)"
BORROWER=$DEPLOYER  # demo borrower
stellar contract invoke --source $BORROWER --network $NET --id "$ZKU" -- \
    request_credit --borrower "$ADMIN_G" --seal "$SEAL" --journal "$JOURNAL"

echo "==> 7. Show the unlocked credit line"
stellar contract invoke --send=no --source $DEPLOYER --network $NET --id "$ZKU" -- \
    credit_line --borrower "$ADMIN_G"

echo "✅ E2E complete. Contract: $ZKU  USDC: $USDC_SAC"
