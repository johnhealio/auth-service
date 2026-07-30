resource "google_artifact_registry_repository" "auth_service" {
  project       = var.project_id
  location      = var.region
  repository_id = "auth-service"
  format        = "DOCKER"
  description   = "Container images for the deployed auth-service Cloud Run service."

  depends_on = [google_project_service.artifactregistry]
}
