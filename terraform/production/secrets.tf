# Empty container only — the actual secret value is never set here (never
# committed, never in Terraform state as a literal). See README.md (or
# deploy.sh) for the out-of-band `gcloud secrets versions add` step and why
# the apply has to happen in phases. The IAM grant letting Cloud Run read
# this secret lives in iam.tf, alongside the runtime service account's
# other roles.
resource "google_secret_manager_secret" "jwt_signing_secret" {
  project   = var.project_id
  secret_id = "jwt-signing-secret"

  replication {
    auto {}
  }

  depends_on = [google_project_service.secretmanager]
}
