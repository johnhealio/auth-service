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

        # min_instance_count = 0 means every scale-from-zero request pays a
        # cold start. This grants full CPU during container/app startup
        # (rather than the throttled-until-first-request default), at no
        # steady-state cost — free given this service already scales to
        # zero.
        startup_cpu_boost = true
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
    google_project_iam_member.cloud_run_log_writer,
    google_project_iam_member.cloud_run_metric_writer,
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
