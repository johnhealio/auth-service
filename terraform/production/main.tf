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
# apply sequence — it is NOT a single `terraform apply`.

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

resource "google_project_service" "serviceusage" {
  project            = var.project_id
  service            = "serviceusage.googleapis.com"
  disable_on_destroy = false
}

resource "google_project_service" "iam" {
  project            = var.project_id
  service            = "iam.googleapis.com"
  disable_on_destroy = false
  depends_on         = [google_project_service.serviceusage]
}

resource "google_project_service" "firestore" {
  project            = var.project_id
  service            = "firestore.googleapis.com"
  disable_on_destroy = false
  depends_on         = [google_project_service.serviceusage]
}

resource "google_project_service" "run" {
  project            = var.project_id
  service            = "run.googleapis.com"
  disable_on_destroy = false
  depends_on         = [google_project_service.serviceusage]
}

resource "google_project_service" "artifactregistry" {
  project            = var.project_id
  service            = "artifactregistry.googleapis.com"
  disable_on_destroy = false
  depends_on         = [google_project_service.serviceusage]
}

resource "google_project_service" "secretmanager" {
  project            = var.project_id
  service            = "secretmanager.googleapis.com"
  disable_on_destroy = false
  depends_on         = [google_project_service.serviceusage]
}

# Dedicated least-privilege identity for the deployed service — distinct
# from the dev VM's much broader datastore.owner identity in
# terraform/dev-bootstrap/.
resource "google_service_account" "cloud_run" {
  project      = var.project_id
  account_id   = var.service_account_id
  display_name = "auth-service Cloud Run runtime identity"
  description  = "Least-privilege identity for the deployed auth-service Cloud Run service (Module 8)."
  depends_on   = [google_project_service.iam]
}

# Named database, separate from dev's auth-service-dev — delete protection
# enabled (unlike dev, which the VM identity needs to be able to
# create/delete for test purposes).
resource "google_firestore_database" "prod" {
  project                 = var.project_id
  name                    = var.database_name
  location_id             = var.region
  type                    = "FIRESTORE_NATIVE"
  delete_protection_state = "DELETE_PROTECTION_ENABLED"

  depends_on = [google_project_service.firestore]
}

resource "google_artifact_registry_repository" "auth_service" {
  project       = var.project_id
  location      = var.region
  repository_id = "auth-service"
  format        = "DOCKER"
  description   = "Container images for the deployed auth-service Cloud Run service."

  depends_on = [google_project_service.artifactregistry]
}

# Empty container only — the actual secret value is never set here (never
# committed, never in Terraform state as a literal). See README.md for the
# out-of-band `gcloud secrets versions add` step and why the apply has to
# happen in phases.
resource "google_secret_manager_secret" "jwt_signing_secret" {
  project   = var.project_id
  secret_id = "jwt-signing-secret"

  replication {
    auto {}
  }

  depends_on = [google_project_service.secretmanager]
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

resource "google_cloud_run_v2_service" "auth_service" {
  project  = var.project_id
  name     = "auth-service"
  location = var.region
  ingress  = "INGRESS_TRAFFIC_ALL"

  template {
    service_account = google_service_account.cloud_run.email

    scaling {
      min_instance_count = 0
      max_instance_count = 3
    }

    # Bounds worst-case Argon2 memory pressure (m_cost x concurrency,
    # per CLAUDE.md's Module 3 reasoning) to ~190 MiB per instance instead
    # of Cloud Run's default-concurrency ~1.5 GiB worst case, given no
    # rate limiting exists yet (that's Module 10) to bound it otherwise.
    max_instance_request_concurrency = 10

    containers {
      image = var.container_image

      resources {
        limits = {
          cpu    = "1"
          memory = "512Mi"
        }
      }

      ports {
        container_port = 8080
      }

      startup_probe {
        http_get {
          path = "/healthz"
        }
        initial_delay_seconds = 0
        timeout_seconds       = 3
        period_seconds        = 5
        failure_threshold     = 3
      }

      env {
        name  = "FIRESTORE_PROJECT_ID"
        value = var.project_id
      }
      env {
        name  = "FIRESTORE_DATABASE_ID"
        value = google_firestore_database.prod.name
      }
      env {
        # Cloud Run's own URL isn't known until after the first apply —
        # see README.md's two-phase apply instructions. Leave the
        # placeholder default for the first apply.
        name  = "PUBLIC_BASE_URL"
        value = var.public_base_url
      }
      env {
        name = "JWT_SIGNING_SECRET"
        value_source {
          secret_key_ref {
            secret  = google_secret_manager_secret.jwt_signing_secret.secret_id
            version = "latest"
          }
        }
      }
    }
  }

  depends_on = [
    google_project_service.run,
    google_project_iam_member.cloud_run_datastore_user,
    google_secret_manager_secret_iam_member.cloud_run_secret_access,
    google_artifact_registry_repository.auth_service,
  ]
}

# This is an auth service — registration/login must be reachable without
# pre-existing credentials. Public access is intentional, not an oversight.
resource "google_cloud_run_v2_service_iam_member" "public_invoker" {
  project  = var.project_id
  location = var.region
  name     = google_cloud_run_v2_service.auth_service.name
  role     = "roles/run.invoker"
  member   = "allUsers"
}
