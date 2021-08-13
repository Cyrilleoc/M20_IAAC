terraform {
  backend "s3" {
    bucket         = "terraformsstate"
    key            = "dev/terraform.tfstate"
    dynamodb_table = "Terraform_State"
    region         = "us-east-1"
  }
}
