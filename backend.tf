terraform {
  backend "s3" {
    bucket = "terraformsstate"
    key    = "dev/terraform.tfstate"
    region = "us-east-1"
  }
}