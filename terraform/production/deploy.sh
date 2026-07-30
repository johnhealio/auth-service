#!/usr/bin/env bash
# Scripts the phased apply sequence documented in README.md (Module 8).
# Run from a machine authenticated with sufficient GCP privileges — your
# laptop, not the Claude Code VM (its own service account has no IAM
# permissions on the project, by design). Requires gcloud, docker, and
# terraform on PATH.
#
# Usage: ./deploy.sh vX.Y.Z
#
# What this replaces manual copy/paste for:
#   - building and pushing the image with the correct --platform (Cloud
#     Run is linux/amd64; a plain `docker build` on an Apple Silicon
#     laptop would otherwise produce an arm64 image)
#   - creating the empty Secret Manager container before it has a value
#   - populating jwt-signing-secret out-of-band, but only on a genuinely
#     first deploy — a naive "always add a new version" step would rotate
#     the signing secret (and invalidate every live session) on every
#     redeploy
#   - the two-phase apply forced by PUBLIC_BASE_URL not being known until
#     after Cloud Run first creates the service, but skipping the
#     placeholder round-trip entirely on redeploys, where the real URL is
#     already known from state
#
# Each `terraform apply` below still prompts for interactive approval
# (no -auto-approve) — this script removes manual-step error, not review.

set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "Usage: $0 <image-tag, e.g. v0.8.0>" >&2
  exit 1
fi

TAG="$1"
PROJECT_ID="johnhealio-claude-code"
REGION="us-central1"
IMAGE="${REGION}-docker.pkg.dev/${PROJECT_ID}/auth-service/auth-service:${TAG}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"

cd "${SCRIPT_DIR}"
terraform init -input=false

echo "==> Building and pushing ${IMAGE}"
gcloud auth configure-docker "${REGION}-docker.pkg.dev" --quiet
docker build --platform linux/amd64 -t "${IMAGE}" "${REPO_ROOT}"
docker push "${IMAGE}"

echo "==> Ensuring the Secret Manager container exists"
terraform apply -target=google_secret_manager_secret.jwt_signing_secret

if ! gcloud secrets versions list jwt-signing-secret \
    --project="${PROJECT_ID}" --format="value(name)" | grep -q .; then
  echo "==> No existing secret version — populating jwt-signing-secret"
  openssl rand -hex 32 | gcloud secrets versions add jwt-signing-secret \
    --project="${PROJECT_ID}" --data-file=-
else
  echo "==> jwt-signing-secret already has a version — not overwriting (would invalidate live sessions)"
fi

# Only the first-ever deploy needs the placeholder-then-real-URL dance:
# once the service exists, its URL is already known from state.
EXISTING_URL=""
if terraform state show google_cloud_run_v2_service.auth_service >/dev/null 2>&1; then
  EXISTING_URL="$(terraform output -raw cloud_run_url 2>/dev/null || true)"
fi

if [[ -n "${EXISTING_URL}" ]]; then
  echo "==> Existing deployment found (${EXISTING_URL}) — single apply"
  terraform apply -var="container_image=${IMAGE}" -var="public_base_url=${EXISTING_URL}"
  URL="${EXISTING_URL}"
else
  echo "==> No existing deployment — first apply with a placeholder PUBLIC_BASE_URL"
  echo "    (/healthz will work after this; DPoP-protected endpoints won't yet)"
  terraform apply -var="container_image=${IMAGE}"
  URL="$(terraform output -raw cloud_run_url)"
  echo "==> Cloud Run assigned: ${URL}"
  echo "==> Re-applying with the real PUBLIC_BASE_URL"
  terraform apply -var="container_image=${IMAGE}" -var="public_base_url=${URL}"
fi

echo "==> Done. Verify with: curl ${URL}/healthz"
