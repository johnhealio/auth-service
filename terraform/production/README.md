# Production deployment (Module 8)

Run everything below from a machine authenticated with sufficient GCP
privileges (your laptop, not the Claude Code VM — its own service account
has no IAM permissions on the project, by design). Requires `gcloud`,
`docker`, and `terraform` installed locally.

This is **not** a single `terraform apply`. Two things force a phased
sequence:

1. Cloud Run's `JWT_SIGNING_SECRET` env var is sourced from Secret
   Manager's `latest` version, which has to exist before Cloud Run can
   deploy — but the secret's actual value must never be a literal in
   Terraform code or state (see CLAUDE.md's "no secrets committed"
   constraint), so it's populated out-of-band between two applies.
2. The DPoP `PUBLIC_BASE_URL` env var needs to be the Cloud Run service's
   own `https://...run.app` URL, which isn't known until *after* Cloud Run
   creates the service — a real circular dependency, resolved the same way
   as (1): deploy once with a placeholder, then re-apply with the real URL.

## Sequence

```bash
cd terraform/production
terraform init

# 1. Build and push the image first (tag matches the repo's vX.Y.Z convention)
gcloud auth configure-docker us-central1-docker.pkg.dev
cd ../..
docker build -t us-central1-docker.pkg.dev/johnhealio-claude-code/auth-service/auth-service:v0.6.0 .
docker push us-central1-docker.pkg.dev/johnhealio-claude-code/auth-service/auth-service:v0.6.0
cd terraform/production

# 2. Create just the empty Secret Manager container (and everything else
#    that doesn't depend on the secret having a value or Cloud Run existing)
terraform apply -target=google_secret_manager_secret.jwt_signing_secret

# 3. Populate the secret out-of-band — never via Terraform
openssl rand -hex 32 | gcloud secrets versions add jwt-signing-secret \
  --project=johnhealio-claude-code --data-file=-

# 4. First full apply — deploys Cloud Run with a placeholder PUBLIC_BASE_URL.
#    /healthz will work at this point; DPoP-protected endpoints won't yet.
terraform apply \
  -var="container_image=us-central1-docker.pkg.dev/johnhealio-claude-code/auth-service/auth-service:v0.6.0"

# 5. Read the real URL Cloud Run assigned
terraform output cloud_run_url

# 6. Re-apply with the real URL, so DPoP htu validation matches reality
terraform apply \
  -var="container_image=us-central1-docker.pkg.dev/johnhealio-claude-code/auth-service/auth-service:v0.6.0" \
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

The `roles/datastore.user` binding should show a `condition` restricting it
to `projects/johnhealio-claude-code/databases/auth-service-prod` — not a
bare project-wide grant.

## Redeploying after a code change

Bump the version (`Cargo.toml` + tag, same as every prior module), rebuild
and push the image with the new tag, then:

```bash
terraform apply -var="container_image=...:vX.Y.Z" -var="public_base_url=<unchanged>"
```

`public_base_url` doesn't change between deploys once set correctly — only
`container_image` does.
