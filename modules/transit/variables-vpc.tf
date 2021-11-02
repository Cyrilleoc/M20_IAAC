variable "environment" {
  type        = string
  default     = "development"
  description = "Environment (development, test, or production)"
}

variable "transit_vpc_name" {
  type        = string
  default     = "TransitVPC"
  description = "Transit VPC Name"
}

variable "transit_cidr" {
  type        = string
  default     = "10.0.0.0/24"
  description = "CIDR block for Transit VPC"
}

variable "bastion_ssh_cidr" {
  type        = string
  default     = "0.0.0.0/0"
  description = "The CIDR Allowed SSH access to the bastion host"
}

variable "transit_dmz_subnet_A_cidr" {
  type        = string
  default     = "10.0.0.0/26"
  description = "CIDR block for Transit AZ-1a subnet"
}

variable "transit_dmz_subnet_B_cidr" {
  type        = string
  default     = "10.0.0.64/26"
  description = "CIDR block for Transit AZ-1b subnet"
}

variable "transit_private_subnet_A_cidr" {
  type        = string
  default     = "10.0.0.128/26"
  description = "CIDR block for Transit AZ-1a subnet"
}

variable "transit_private_subnet_B_cidr" {
  type        = string
  default     = "10.0.0.192/26"
  description = "CIDR block for Transit AZ-1b subnet"
}

variable "region_az1_name" {
  type        = string
  default     = "us-east-1a"
  description = "Availability Zone 1 Name in Region"
}

variable "region_az2_name" {
  type        = string
  default     = "us-east-1b"
  description = "Availability Zone 2 Name in Region"
}

