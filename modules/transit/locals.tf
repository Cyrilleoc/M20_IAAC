locals {
  build_s3_url     = "https://s3.amazonaws.com"
  region_root_url  = "amazonaws.com"
  region_partition = "aws" # aws-us-gov used in iam-roles

  caller_account_id = data.aws_caller_identity.current.account_id
  caller_aws_region = data.aws_region.current.name

  #  SAML URL for GEOAxIS Federated Access
  # saml_us_east_1      = "https://signin.aws.amazon.com/saml"
  # saml_us_gov_west_1  = "https://signin.amazonaws-us-gov.com/saml"
  # saml_us_isob_east_1 = "https://signin.sc2shome.sgov.gov/saml"

  # https://stackoverflow.com/questions/66803123/terraform-interpolation-of-locals-map-with-key-defined-in-a-variable
  saml_map = {
    us_east_1 = {
      saml = "https://signin.aws.amazon.com/saml"
    }
    us_gov_west_1 = {
      saml = "https://signin.amazonaws-us-gov.com/saml"
    }
    us_isob_east_1 = {
      saml = "https://signin.sc2shome.sgov.gov/saml"
    }
  }

  # Conditions
  nipr_resource      = var.region_partition == "aws" ? true : false
  gov_cloud_resource = var.region_partition == "aws-us-gov" ? true : false
  sipr_resource      = var.region_partition == "aws-iso-b" ? true : false
  jwics_resource     = var.region_partition == "aws-iso" ? true : false

}
