variable "project_id" {
  description = "GCP project this VM and the dev Firestore database live in."
  type        = string
  default     = "johnhealio-claude-code"
}

variable "region" {
  description = "Firestore location for the dev database."
  type        = string
  default     = "us-central1"
}

variable "database_name" {
  description = "Named Firestore database for dev/test use (kept separate from any future (default) database)."
  type        = string
  default     = "auth-service-dev"
}

variable "vm_service_account_email" {
  description = "Service account attached to the Claude Code VM, granted Firestore access."
  type        = string
  default     = "claude-code-vm@johnhealio-claude-code.iam.gserviceaccount.com"
}
