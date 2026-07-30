# Production IaC for the deployed auth-service Cloud Run service (Module 8).
#
# Separate Terraform root/state from terraform/dev-bootstrap/ on purpose —
# different lifecycle and blast radius. Lives in the same GCP project as
# dev (johnhealio-claude-code) by deliberate choice: isolation comes from a
# separate Firestore database, a dedicated least-privilege service account,
# and a database-scoped IAM condition, not a second project. See
# CLAUDE.md's Module 8 decisions for the full reasoning.
#
# Run this from a machine authenticated with sufficient privileges to
# create service accounts, grant IAM roles, and enable APIs (the Claude
# Code VM's own service account does NOT have these permissions, by
# design — same as terraform/dev-bootstrap/). See README.md for the full
# apply sequence (or ./deploy.sh, which scripts it) — it is NOT a single
# `terraform apply`.
#
# Files in this root, split by concern rather than one main.tf:
#   providers.tf        - this file: provider/version config
#   apis.tf              - project service (API) enablement
#   iam.tf                - the runtime service account and every role
#                          granted to it
#   firestore.tf          - the production Firestore database
#   artifact_registry.tf  - the image repository
#   secrets.tf             - the JWT signing secret container
#   cloud_run.tf            - the Cloud Run service and its public-invoker
#                          binding
# Terraform merges all .tf files in a directory identically regardless of
# name, so this split is pure organization — no behavior change from the
# single-file version.

terraform {
  required_version = ">= 1.5"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 6.0"
    }
  }
}

provider "google" {
  project = var.project_id
}
