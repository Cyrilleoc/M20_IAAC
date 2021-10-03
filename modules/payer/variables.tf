variable "logs_bucket" {
  type        = string
  default     = "tenant-logs-storage0"
  description = "S3 bucket name for log storage"
  validation {
    # regex(...) fails if it cannot find a match
    condition     = can(regex("^[0-9a-zA-Z]+([0-9a-zA-Z-.]*[0-9a-zA-Z])*$", var.logs_bucket))
    error_message = "Invalid bucket name."
    # Bucket name can include numbers, lowercase letters, uppercase
    # letters, periods (.), and hyphens (-). It cannot start or end with a hyphen (-).
  }
}

variable "cloudtrail_to_cloudwatch_logs" {
  type        = bool
  default     = true
  description = <<EOT
True if a CloudWatch Logs log group was manually created for CloudTrail
Logs to be sent to CloudWatch Logs in this account
EOT
}

variable "cloudtrail_log_group" {
  type        = string
  default     = "cloudtrail"
  description = "Name of CloudWatch Logs log group local destination for CloudTrail Logs"
}

variable "billing_bucket" {
  type        = string
  default     = "unique-bucket-name"
  description = "S3 bucket name for billing reports storage"
  validation {
    # regex(...) fails if it cannot find a match
    condition     = can(regex("^[0-9a-zA-Z]+([0-9a-zA-Z-.]*[0-9a-zA-Z])*$", var.billing_bucket))
    error_message = <<EOT
A bucket name can include numbers, lowercase
letters, uppercase letters, periods (.), and hyphens (-). It cannot start or
end with a hyphen (-).
EOT
  }
}

variable "billing_principal" {
  type        = string
  default     = "386209384616"
  description = "Domain specific principal for billing report delivery"
}
