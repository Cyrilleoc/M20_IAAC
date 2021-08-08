locals {
    build_s3_url = "https://s3.amazonaws.com"
    region_root_url = "amazonaws.com"
    region_partition = "aws"
    caller_account_id = data.aws_caller_identity.current.account_id
    caller_aws_region = data.aws_region.current.name
    cloudwatch_logs_loggroup = var.cloudtrail_to_cloudwatch_logs ? 1 : 0
    cloudtrail_logging_local = var.cloudtrail_to_cloudwatch_logs ? 0 : 1    
}