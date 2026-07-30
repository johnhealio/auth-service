# Production deployment (Module 8)

Run everything below from a machine authenticated with sufficient GCP
privileges (your laptop, not the Claude Code VM — its own service account
has no IAM permissions on the project, by design). Requires `gcloud`,
`docker`, and `terraform` installed locally.

## Files

Split by concern, not one `main.tf` — Terraform merges every `.tf` file in
a directory identically regardless of name, so this is pure organization:

- `providers.tf` — provider/version config
- `apis.tf` — project API enablement
- `iam.tf` — the runtime service account and every role granted to it
  (Secret Manager access, scoped Firestore access, logging/metrics writers)
- `firestore.tf` — the production Firestore database
- `artifact_registry.tf` — the image repository
- `secrets.tf` — the JWT signing secret container (value populated
  out-of-band, never in Terraform)
- `cloud_run.tf` — the Cloud Run service and its public-invoker binding
- `deploy.sh` — scripts the phased sequence below

## Quick path

```bash
./deploy.sh v0.9.0
```

Builds and pushes the image (with the correct `--platform linux/amd64` —
see the note below), creates the Secret Manager container, populates it
only if it doesn't already have a value (so a redeploy never rotates the
live signing secret), and runs one or two `terraform apply`s depending on
whether this is the first deploy or a redeploy. Every `apply` still stops
for interactive approval — the script removes manual-step error, not
review. Read on for what it's doing and why, or if you'd rather run each
step by hand.

## Why this isn't a single `terraform apply`

Two things force a phased sequence, whether run via `deploy.sh` or by hand:

1. Cloud Run's `JWT_SIGNING_SECRET` env var is sourced from Secret
   Manager's `latest` version, which has to exist before Cloud Run can
   deploy — but the secret's actual value must never be a literal in
   Terraform code or state (see CLAUDE.md's "no secrets committed"
   constraint), so it's populated out-of-band between two applies.
2. The DPoP `PUBLIC_BASE_URL` env var needs to be the Cloud Run service's
   own `https://...run.app` URL, which isn't known until *after* Cloud Run
   creates the service — a real circular dependency, resolved the same way
   as (1): deploy once with a placeholder, then re-apply with the real URL.
   This round only applies on a genuine first deploy — once the service
   exists, its URL is already known from state, so a redeploy is a single
   `apply`.

## Manual sequence

```bash
cd terraform/production
terraform init

# 1. Create just the Artifact Registry repo and the empty Secret Manager
#    container (and everything else that doesn't depend on the image or
#    Cloud Run existing). The repo has to exist before step 2 can push
#    into it — on a genuinely first deploy, neither resource exists yet.
terraform apply \
  -target=google_artifact_registry_repository.auth_service \
  -target=google_secret_manager_secret.jwt_signing_secret

# 2. Build and push the image (tag matches the repo's vX.Y.Z convention).
#    --platform linux/amd64 is required: Cloud Run runs amd64, and a plain
#    `docker build` on an Apple Silicon laptop would otherwise produce an
#    arm64 image (or a slow QEMU-emulated one) with no error until deploy.
gcloud auth configure-docker us-central1-docker.pkg.dev
cd ../..
docker build --platform linux/amd64 \
  -t us-central1-docker.pkg.dev/johnhealio-claude-code/auth-service/auth-service:v0.9.0 .
docker push us-central1-docker.pkg.dev/johnhealio-claude-code/auth-service/auth-service:v0.9.0
cd terraform/production

# 3. Populate the secret out-of-band — never via Terraform. Skip this step
#    on a redeploy: re-adding a version rotates the signing secret and
#    invalidates every live session.
openssl rand -hex 32 | gcloud secrets versions add jwt-signing-secret \
  --project=johnhealio-claude-code --data-file=-

# 4. First full apply — deploys Cloud Run with a placeholder PUBLIC_BASE_URL.
#    /healthz will work at this point; DPoP-protected endpoints won't yet.
terraform apply \
  -var="container_image=us-central1-docker.pkg.dev/johnhealio-claude-code/auth-service/auth-service:v0.9.0"

# 5. Read the real URL Cloud Run assigned
terraform output cloud_run_url

# 6. Re-apply with the real URL, so DPoP htu validation matches reality
terraform apply \
  -var="container_image=us-central1-docker.pkg.dev/johnhealio-claude-code/auth-service/auth-service:v0.9.0" \
  -var="public_base_url=<the URL from step 5>"
```

## Verify

```bash
CLOUD_RUN_URL=$(terraform output -raw cloud_run_url)

curl "$CLOUD_RUN_URL/healthz"
# expect: 200, body "ok"
```

Then a full smoke test against the live URL — register → login → refresh →
`/me` — the same DPoP-proof-construction approach used for this project's
manual local verification (Modules 6/7), just pointed at `$CLOUD_RUN_URL`
instead of `localhost:8080`. If login/`/me` fail with a DPoP `htu`
mismatch specifically, `public_base_url` doesn't exactly match the deployed
URL (scheme/host/port/path are matched strictly — see `src/dpop.rs`) —
that's the most likely first-deploy gotcha.

Finally, confirm least-privilege IAM actually took effect (not just that
the config *says* it should have):

```bash
gcloud projects get-iam-policy johnhealio-claude-code \
  --flatten="bindings[].members" \
  --filter="bindings.members:$(terraform output -raw service_account_email)"
```

The command above shows only *project-level* bindings — it should return
exactly three:

- `roles/datastore.user`, with a `condition` restricting it to
  `projects/johnhealio-claude-code/databases/auth-service-prod` — not a
  bare project-wide grant
- `roles/logging.logWriter` and `roles/monitoring.metricWriter`, both
  unconditional project grants — required because this is a custom
  runtime service account rather than the default Compute Engine one,
  which gets equivalent access implicitly.

The runtime service account holds a fourth role, `roles/secretmanager.secretAccessor`,
but it won't show up above — it's granted on the secret's own IAM policy,
not the project's, so check it separately:

```bash
gcloud secrets get-iam-policy jwt-signing-secret --project=johnhealio-claude-code
```

(Pulling the container image itself doesn't go through this service
account at all — that's the Cloud Run Service Agent, which Google
auto-grants Artifact Registry read access to for same-project
repositories when the Cloud Run API is enabled; nothing to configure
here.)

## Redeploying after a code change

Bump the version (`Cargo.toml` + tag, same as every prior module), then
either `./deploy.sh vX.Y.Z` or, by hand:

```bash
docker build --platform linux/amd64 -t ...:vX.Y.Z .
docker push ...:vX.Y.Z
terraform apply -var="container_image=...:vX.Y.Z" -var="public_base_url=<unchanged>"
```

`public_base_url` doesn't change between deploys once set correctly — it's
a Terraform input variable, not tracked resource state, so it must be
passed explicitly on every apply or it reverts to `variables.tf`'s
placeholder default. `deploy.sh` handles this automatically by reading the
already-deployed URL from state.
