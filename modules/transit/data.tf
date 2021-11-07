data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

data "aws_iam_policy_document" "transit_config_role_inline_policy" {
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

data "aws_iam_policy_document" "transit_logs_bucket_inline_policy" {
  statement {
    sid       = "ELBAccessLogs20171110"
    effect    = "Allow"
    actions   = ["s3:PutObject"]
    resources = ["arn:${local.region_partition}:s3:::${var.logs_bucket}/ElbAccessLogs/AWSLogs/${local.caller_account_id}/*"]
    principals {
      type        = "AWS"
      identifiers = ["arn:${local.region_partition}:iam::${var.elb_principle}:root"]
    }
  }

  statement {
    sid       = "AWSCloudTrailAclCheck20171201"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = ["arn:${local.region_partition}:s3:::${var.logs_bucket}"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.${local.caller_aws_region}"]
    }
  }

  statement {
    sid       = "AWSConfigAclCheck20171201"
    effect    = "Allow"
    actions   = ["s3:GetBucketAcl"]
    resources = ["arn:${local.region_partition}:s3:::${var.logs_bucket}"]
    principals {
      type        = "Service"
      identifiers = ["config.${local.caller_aws_region}"]
    }
  }

  statement {
    sid     = "AWSCloudTrailWrite20171201"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    resources = [
      "arn:${local.region_partition}:s3:::${var.logs_bucket}/cloudtrail/AWSLogs/${local.caller_account_id}/*",
      "arn:${local.region_partition}:s3:::${var.logs_bucket}/cloudtrail/AWSLogs/${var.master_payer_account_id}/*",
      "arn:${local.region_partition}:s3:::${var.logs_bucket}/cloudtrail/AWSLogs/${var.tenant_account_id}/*"
    ]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.${local.caller_aws_region}"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
  }

  statement {
    sid     = "AWSConfigBucketDelivery20171201"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    resources = [
      "arn:${local.region_partition}:s3:::${var.logs_bucket}/config/AWSLogs/${var.master_payer_account_id}/Config/*",
      "arn:${local.region_partition}:s3:::${var.logs_bucket}/config/AWSLogs/${var.tenant_account_id}/Config/*"
    ]
    principals {
      type        = "Service"
      identifiers = ["config.${local.caller_aws_region}"]
    }
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
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

