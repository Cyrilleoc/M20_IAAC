variable "role_timeout_settings" {
  type        = number
  default     = 43200
  description = "Timeout value applied to all IAM roles defined in this stack. In seconds. Min 3600, max 43200"
}

variable "cap_account" {
  type        = string
  default     = "593664963477" # Adding Pro_User account ID for now
  description = "Account number for CAP federation"
}


# variable "saml_url" {
#   type        = string
#   default     = "https://signin.amazonaws-us-gov.com/saml" # add this as default for now
#   description = "SAML URL for GEOAxIS Federated Access"
# }

