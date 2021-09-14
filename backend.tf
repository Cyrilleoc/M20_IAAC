terraform {
  backend "s3" {
    bucket         = "terraformsstate"
    key            = "dev/terraform.tfstate"
    dynamodb_table = "Terraform-statefile"
    region         = "us-east-1"
  }
}
