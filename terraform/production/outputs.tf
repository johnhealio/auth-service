output "cloud_run_url" {
  value       = google_cloud_run_v2_service.auth_service.uri
  description = "The deployed service's URL. Use this to set public_base_url on the second apply, and to run the verification smoke test."
}

output "service_account_email" {
  value       = google_service_account.cloud_run.email
  description = "The Cloud Run service's dedicated runtime identity."
}

output "artifact_registry_repo" {
  value       = "${var.region}-docker.pkg.dev/${var.project_id}/${google_artifact_registry_repository.auth_service.repository_id}"
  description = "Push container images here, e.g. <this>/auth-service:vX.Y.Z."
}

output "jwt_signing_secret_id" {
  value       = google_secret_manager_secret.jwt_signing_secret.secret_id
  description = "Secret Manager secret ID to populate via `gcloud secrets versions add` before the second apply."
}
