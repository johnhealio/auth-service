# Dedicated least-privilege identity for the deployed service — distinct
# from the dev VM's much broader datastore.owner identity in
# terraform/dev-bootstrap/. Every role this identity holds is granted
# explicitly below; nothing is inherited from a broader project role.
resource "google_service_account" "cloud_run" {
  project      = var.project_id
  account_id   = var.service_account_id
  display_name = "auth-service Cloud Run runtime identity"
  description  = "Least-privilege identity for the deployed auth-service Cloud Run service (Module 8)."
  depends_on   = [google_project_service.iam]
}

# Scoped to this one secret, not project-wide Secret Manager access.
resource "google_secret_manager_secret_iam_member" "cloud_run_secret_access" {
  project   = var.project_id
  secret_id = google_secret_manager_secret.jwt_signing_secret.secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${google_service_account.cloud_run.email}"
}

# roles/datastore.user (entity CRUD only — excludes database create/delete,
# unlike dev-bootstrap's roles/datastore.owner), further restricted via an
# IAM condition to this specific database. Firestore IAM has no
# collection-level scoping — this is the finest grain actually available
# (Firestore Security Rules could go finer, but aren't enforced for
# service-account/gRPC access, only Firebase client-SDK access with
# end-user auth, which doesn't apply to how this app talks to Firestore).
resource "google_project_iam_member" "cloud_run_datastore_user" {
  project = var.project_id
  role    = "roles/datastore.user"
  member  = "serviceAccount:${google_service_account.cloud_run.email}"

  condition {
    title       = "prod-database-only"
    description = "Restrict to the production Firestore database only"
    expression  = "resource.name == \"projects/${var.project_id}/databases/${google_firestore_database.prod.name}\""
  }
}

# Logs/metrics writer roles — required because this is a custom (non-
# default) runtime service account. The default Compute Engine service
# account gets equivalent access implicitly via a legacy broad grant;
# a dedicated SA like this one gets nothing until granted explicitly.
# Google's own "Cloud Run service identity" documentation calls these two
# roles out by name for exactly this case. No IAM condition: neither role
# is scoped to a specific log sink or metric resource the way the Firestore
# grant above is scoped to one database, so an unconditional project grant
# is the standard/expected shape for these.
resource "google_project_iam_member" "cloud_run_log_writer" {
  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${google_service_account.cloud_run.email}"
}

resource "google_project_iam_member" "cloud_run_metric_writer" {
  project = var.project_id
  role    = "roles/monitoring.metricWriter"
  member  = "serviceAccount:${google_service_account.cloud_run.email}"
}

# Not a Terraform resource: pulling the container image itself is done by
# the Cloud Run Service Agent (service-<project-number>@serverless-robot-
# prod.iam.gserviceaccount.com), not this runtime service account, and
# Google auto-grants that agent Artifact Registry read access on same-
# project repositories when the Cloud Run API is enabled. Documented here
# so this file is a complete account of the IAM surface even though there's
# nothing to declare for it.
