resource "aws_iam_role" "transit_config_role" {
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "config.${local.region_root_url}"
        }
      },
    ]
  })

  managed_policy_arns = ["arn:${local.region_partition}:iam::aws:policy/service-role/AWSConfigRole"]

  inline_policy {
    name = "config-s3-delivery"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Action   = "s3:GetBucketAcl"
          Effect   = "Allow"
          Resource = "arn:${local.region_partition}:s3:::${var.logs_bucket}"
        },
        {
          Action   = "s3:PutObject"
          Effect   = "Allow"
          Resource = "arn:${local.region_partition}:s3:::${var.logs_bucket}/config/AWSLogs/${local.caller_account_id}/*"
        },
        {
          Action   = "config:Put*"
          Effect   = "Allow"
          Resource = "*"
        }
      ]
    })
  }
}

resource "aws_iam_role" "cloudwatch_logs_role" {
  # revist this condition
  #   count = var.cloudtrail_to_cloudwatch_logs ? 1 : 0

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.${local.region_root_url}"
        }
      },
    ]
  })
  path = "/"
  inline_policy {
    name = "cloudwatchlogsrole"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Sid      = "AWSCloudTrailCreateLogStream20141101"
          Action   = "logs:CreateLogStream"
          Effect   = "Allow"
          Resource = "arn:${local.region_partition}:logs:${local.caller_aws_region}:${local.caller_account_id}:log-group:${var.cloudtrail_log_group}:log-stream:*"
        },
        {
          Sid      = "AWSCloudTrailPutLogEvents20141101"
          Action   = "logs:PutLogEvents"
          Effect   = "Allow"
          Resource = "arn:${local.region_partition}:logs:${local.caller_aws_region}:${local.caller_account_id}:log-group:${var.cloudtrail_log_group}:log-stream:*"
        }
      ]
    })
  }
}

resource "aws_cloudtrail" "cloudtrail_logging_local" {
  #   count                         = var.cloudtrail_to_cloudwatch_logs ? 0 : 1
  name                          = "cloudtrail_logging_local"
  s3_bucket_name                = var.logs_bucket
  s3_key_prefix                 = "cloudtrail"
  enable_logging                = true
  enable_log_file_validation    = true
  include_global_service_events = true
  is_multi_region_trail         = true
}


resource "aws_cloudtrail" "cloudtrail_logging_dual" {
  # count                         = var.cloudtrail_to_cloudwatch_logs ? 1 : 0
  name                          = "cloudtrail_logging_dual"
  s3_bucket_name                = var.logs_bucket
  s3_key_prefix                 = "cloudtrail"
  enable_logging                = true
  enable_log_file_validation    = true
  include_global_service_events = true
  is_multi_region_trail         = true
  cloud_watch_logs_group_arn    = "arn:${local.region_partition}:logs:${local.caller_aws_region}:${local.caller_account_id}:log-group:${var.cloudtrail_log_group}:*"
  cloud_watch_logs_role_arn     = aws_iam_role.cloudwatch_logs_role.arn
}
