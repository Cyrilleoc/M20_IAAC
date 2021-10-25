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
      }
    ]
  })

  managed_policy_arns = ["arn:${local.region_partition}:iam::aws:policy/service-role/AWSConfigRole"]

  inline_policy {
    name   = "config-s3-delivery"
    policy = data.aws_iam_policy_document.transit_config_role_inline_policy.json
  }
}

resource "aws_s3_bucket" "logs_bucket" {
  bucket = var.logs_bucket
  acl    = "log-delivery-write"

  versioning {
    enabled = true
  }
}

resource "aws_s3_bucket_policy" "logs_bucket_policy" {
  bucket = aws_s3_bucket.logs_bucket.id
  policy = data.aws_iam_policy_document.transit_logs_bucket_inline_policy.json
}

resource "aws_iam_role" "cloudwatch_logs_role" {
  count = var.cloudtrail_to_cloudwatch_logs ? 1 : 0
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "cloudtrail.${local.region_root_url}"
        }
      }
    ]
  })
  path = "/"

  inline_policy {
    name   = "cloudwatchlogsrole"
    policy = data.aws_iam_policy_document.cloudwatch_logs_role_inline_policy.json
  }
}
