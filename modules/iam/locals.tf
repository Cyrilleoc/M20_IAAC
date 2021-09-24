locals {
  build_s3_url     = "https://s3.amazonaws.com"
  region_root_url  = "amazonaws.com"
  region_partition = "aws" # aws-us-gov used in iam-roles

  caller_account_id = data.aws_caller_identity.current.account_id
  caller_aws_region = data.aws_region.current.name

  #  SAML URL for GEOAxIS Federated Access
  saml_url_gov  = "https://signin.amazonaws-us-gov.com/saml"
  saml_url      = "https://signin.aws.amazon.com/saml"
  saml_url_sgov = "https://signin.sc2shome.sgov.gov/saml"

  # region_map = {
  #   "us-east-1" = {
  #     "partition" : "aws",
  #     "saml" : "https://signin.aws.amazon.com/saml"
  #   },
  #   "us-gov-west-1" = {
  #     "partition" : "aws-us-gov",
  #     "saml" : "https://signin.amazonaws-us-gov.com/saml"
  #   },
  #   "us-isob-east-1" = {
  #     "partition" : "aws-iso-b",
  #     "saml" : "https://signin.sc2shome.sgov.gov/saml"
  #   },
  #   "us-iso-east-1" = {
  #     "partition" : "aws-iso"
  #   }
  # }

  # nipr_resource = lookup(local.region_map, local.caller_aws_region, "") 

}
