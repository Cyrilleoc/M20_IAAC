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

variable "config_bucket" {
  type        = string
  default     = "configbucket"
  description = "S3 bucket name for bastion and proxy configuration files"
}

variable "bastion_ami" {
  type        = string
  default     = "ami-8c1be5f6"
  description = "AMI to use for bastion host"
}

variable "proxy_ami" {
  type        = string
  default     = "ami-8c1be5f6"
  description = "AMI to use for proxy host(s)"
}

variable "bastion_key_pair" {
  type        = string
  default     = ""
  description = "Name of existing EC2 key pair for BASTION host"
}

variable "proxy_key_pair" {
  type        = string
  default     = ""
  description = "Name of existing EC2 key pair for proxy hosts"
}

variable "bastion_instance_type" {
  type        = string
  default     = "t2.small"
  description = "Bastion EC2 instance type"
}

variable "proxy_instance_type" {
  type        = string
  default     = "t2.small"
  description = "The instance type for the proxy host"
}

variable "bastion_auto_scale_min" {
  type        = number
  default     = 1
  description = "The lower bound for autoscaling your Bastion fleet"
}

variable "bastion_auto_scale_max" {
  type        = number
  default     = 1
  description = "The upper bound for autoscaling your Bastion fleet"
}

variable "proxy_auto_scale_min" {
  type        = number
  default     = 1
  description = "The lower bound for autoscaling your Proxy fleet"
}

variable "proxy_auto_scale_max" {
  type        = number
  default     = 1
  description = "The upper bound for autoscaling your Proxy fleet"
}

variable "tenant_account_id" {
  type        = string
  default     = "593664963477" # Adding Pro_User account ID for now
  description = "12 Digit Account ID of the Tenant Account"
}

variable "cap_account" {
  type        = string
  default     = "593664963477" # Adding Pro_User account ID for now
  description = "Account number for CAP"
}

variable "region_partition" {
  type        = string
  default     = "aws-us-gov"
  description = "Region Specific Partition"
}


