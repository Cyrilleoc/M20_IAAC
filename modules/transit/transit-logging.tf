# resource "aws_iam_role" "transit_config_role" {
#   assume_role_policy = jsonencode({
#     Version = "2012-10-17"
#     Statement = [
#       {
#         Action = "sts:AssumeRole"
#         Effect = "Allow"
#         Principal = {
#           Service = "config.${local.region_root_url}"
#         }
#       }
#     ]
#   })

#   managed_policy_arns = ["arn:${local.region_partition}:iam::aws:policy/service-role/AWSConfigRole"]

#   inline_policy {
#     name   = "config-s3-delivery"
#     policy = data.aws_iam_policy_document.transit_config_role_inline_policy.json
#   }
# }

# resource "aws_s3_bucket" "logs_bucket" {
#   bucket = var.logs_bucket
#   acl    = "log-delivery-write"

#   versioning {
#     enabled = true
#   }
# }

# resource "aws_s3_bucket_policy" "logs_bucket_policy" {
#   bucket = aws_s3_bucket.logs_bucket.id
#   policy = data.aws_iam_policy_document.transit_logs_bucket_inline_policy.json
# }

# resource "aws_iam_role" "cloudwatch_logs_role" {
#   count = var.cloudtrail_to_cloudwatch_logs ? 1 : 0
#   assume_role_policy = jsonencode({
#     Version = "2012-10-17"
#     Statement = [
#       {
#         Action = "sts:AssumeRole"
#         Effect = "Allow"
#         Principal = {
#           Service = "cloudtrail.${local.region_root_url}"
#         }
#       }
#     ]
#   })
#   path = "/"

#   inline_policy {
#     name   = "cloudwatchlogsrole"
#     policy = data.aws_iam_policy_document.cloudwatch_logs_role_inline_policy.json
#   }
# }

# resource "aws_cloudtrail" "cloudtrail_logging_local" {
#   count                         = var.cloudtrail_to_cloudwatch_logs ? 0 : 1
#   depends_on                    = [aws_s3_bucket_policy.logs_bucket_policy]
#   s3_bucket_name                = var.logs_bucket
#   s3_key_prefix                 = "cloudtrail"
#   enable_logging                = true
#   enable_log_file_validation    = true
#   include_global_service_events = true
#   is_multi_region_trail         = true
# }

# resource "aws_cloudtrail" "cloudtrail_logging_dual" {
#   count                         = var.cloudtrail_to_cloudwatch_logs ? 1 : 0
#   depends_on                    = [aws_s3_bucket_policy.logs_bucket_policy]
#   s3_bucket_name                = var.logs_bucket
#   s3_key_prefix                 = "cloudtrail"
#   enable_logging                = true
#   enable_log_file_validation    = true
#   include_global_service_events = true
#   is_multi_region_trail         = true
#   cloud_watch_logs_group_arn    = "arn:${local.region_partition}:logs:${local.caller_aws_region}:${local.caller_account_id}:log-group:${var.cloudtrail_log_group}:*"
#   cloud_watch_logs_role_arn     = aws_iam_role.cloudwatch_logs_role[0].arn
# }
