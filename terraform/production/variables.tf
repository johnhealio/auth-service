variable "project_id" {
  description = "GCP project the production deployment lives in (same project as dev-bootstrap, isolated via a separate database/service account/IAM condition instead of a separate project)."
  type        = string
  default     = "johnhealio-claude-code"
}

variable "region" {
  description = "Region for Firestore, Artifact Registry, and Cloud Run — kept identical for latency/co-location."
  type        = string
  default     = "us-central1"
}

variable "database_name" {
  description = "Named Firestore database for production, kept separate from dev's auth-service-dev."
  type        = string
  default     = "auth-service-prod"
}

variable "service_account_id" {
  description = "Account ID (not full email) for the dedicated Cloud Run runtime service account."
  type        = string
  default     = "auth-service-run"
}

variable "container_image" {
  description = "Fully-qualified Artifact Registry image reference, e.g. us-central1-docker.pkg.dev/PROJECT/auth-service/auth-service:vX.Y.Z. Built and pushed by hand before applying — see README.md. No default: must be supplied at apply time."
  type        = string
}

variable "public_base_url" {
  description = "The Cloud Run service's own https URL, used for DPoP htu validation. Not knowable until after the first apply — leave the placeholder default for the first apply, then re-apply with the real observed URL (see README.md's two-phase instructions)."
  type        = string
  default     = "https://REPLACE-AFTER-FIRST-APPLY.run.app"
}
