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
