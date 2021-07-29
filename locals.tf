locals {
    build_s3_url = "https://s3.amazonaws.com"
    region_root_url = "amazonaws.com"
    region_partition = "aws"
    caller_account_id = data.aws_caller_identity.current.account_id
}