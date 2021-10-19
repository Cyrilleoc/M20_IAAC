data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

data "aws_iam_policy_document" "cap_account_policy" {
  statement {
    sid     = ""
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Principal"
      identifiers = ["arn:${local.region_partition}:iam::${var.cap_account}:root"]
    }
  }
}

data "aws_iam_policy_document" "payer_config_role_inline_policy" {
  statement {
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = ["arn:${local.region_partition}:s3:::${var.logs_bucket}"]
  }

  statement {
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["arn:${local.region_partition}:s3:::${var.logs_bucket}/config/AWSLogs/${local.caller_account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    effect    = "Allow"
    actions   = ["config:Put*"]
    resources = ["*"]
  }
}

data "aws_iam_policy_document" "cloudwatch_logs_role_inline_policy" {
  statement {
    sid       = "AWSCloudTrailCreateLogStream20141101"
    effect    = "Allow"
    actions   = ["logs:CreateLogStream"]
    resources = ["arn:${local.region_partition}:logs:${local.caller_aws_region}:${local.caller_account_id}:log-group:${var.cloudtrail_log_group}:log-stream:*"]
  }

  statement {
    sid       = "AWSCloudTrailPutLogEvents20141101"
    effect    = "Allow"
    actions   = ["logs:PutLogEvents"]
    resources = ["arn:${local.region_partition}:logs:${local.caller_aws_region}:${local.caller_account_id}:log-group:${var.cloudtrail_log_group}:log-stream:*"]
  }
}


