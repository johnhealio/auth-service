# Dev-environment bootstrap: grants the Claude Code VM's service account
# real Firestore access so Module 3+ integration tests can run against a
# live database instead of an emulator or fake.
#
# NOT the production IaC. The Cloud Run deployment (Module 8) will get its
# own, more tightly scoped service account and role grants — this one is
# intentionally broader (roles/datastore.owner) because it's a dev/test
# identity that also needs to create/delete the database itself.
#
# Run this from a machine authenticated with sufficient privileges to grant
# IAM roles and enable APIs (the VM's own service account does NOT have
# these permissions, by design).

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

resource "google_project_service" "firestore" {
  project            = var.project_id
  service            = "firestore.googleapis.com"
  disable_on_destroy = false

  depends_on = [google_project_service.serviceusage]
}

resource "google_firestore_database" "dev" {
  project     = var.project_id
  name        = var.database_name
  location_id = var.region
  type        = "FIRESTORE_NATIVE"

  depends_on = [google_project_service.firestore]
}

# Additive grant (google_project_iam_member), not google_project_iam_binding —
# a _binding resource is authoritative and would wipe out any other
# principals already holding this role on the project. _member only adds
# this one binding and leaves everything else untouched.
resource "google_project_iam_member" "vm_datastore_owner" {
  project = var.project_id
  role    = "roles/datastore.owner"
  member  = "serviceAccount:${var.vm_service_account_email}"
}
