output "firestore_database_name" {
  value       = google_firestore_database.dev.name
  description = "Full resource name of the dev Firestore database."
}

output "firestore_database_id" {
  value       = var.database_name
  description = "Database ID to set as FIRESTORE_DATABASE_ID when running the service against this dev database."
}
