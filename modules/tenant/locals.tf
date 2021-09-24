locals {
  build_s3_url     = "https://s3.amazonaws.com"
  region_root_url  = "amazonaws.com"
  region_partition = "aws" # aws-us-gov used in iam-roles
  # Adding Pro_User account ID for now
  cap_account       = "593664963477" # Account number for CAP federation
  caller_account_id = data.aws_caller_identity.current.account_id
  caller_aws_region = data.aws_region.current.name
}
