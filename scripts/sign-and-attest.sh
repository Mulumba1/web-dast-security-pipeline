#!/usr/bin/env bash
set -euo pipefail

# Reusable Container Image Signing & CycloneDX SBOM Attestation Script
# Usage: ./scripts/sign-and-attest.sh <image_ref_with_digest> [sbom_path] [private_key] [public_key]

IMAGE_REF="${1:?Usage: $0 <image_ref_with_digest> [sbom_path] [private_key] [public_key]}"
SBOM_PATH="${2:-bom.json}"
PRIVATE_KEY="${3:-cosign.key}"
PUBLIC_KEY="${4:-cosign.pub}"

echo "[1/4] Signing container image digest: ${IMAGE_REF}"
cosign sign --yes --key "${PRIVATE_KEY}" "${IMAGE_REF}"

echo "[2/4] Verifying Cosign image signature..."
cosign verify --key "${PUBLIC_KEY}" "${IMAGE_REF}"

if [[ -f "${SBOM_PATH}" ]]; then
  echo "[3/4] Attaching signed CycloneDX SBOM attestation (${SBOM_PATH})..."
  cosign attest --yes --key "${PRIVATE_KEY}" --predicate "${SBOM_PATH}" --type cyclonedx "${IMAGE_REF}"

  echo "[4/4] Verifying CycloneDX SBOM attestation..."
  cosign verify-attestation --key "${PUBLIC_KEY}" --type cyclonedx "${IMAGE_REF}"
else
  echo "[!] SBOM file '${SBOM_PATH}' not found; skipping attestation step."
  exit 1
fi

echo "[+] Image signature and CycloneDX SBOM attestation verified successfully."
