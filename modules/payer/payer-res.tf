resource "aws_s3_bucket" "billing_bucket" {
  bucket = var.billing_bucket
  acl    = "log-delivery-write"

  versioning {
    enabled = true
  }
}

resource "aws_s3_bucket_policy" "billing_bucket_policy" {
  bucket = aws_s3_bucket.billing_bucket.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "BillingAclPolicyCheck20171206"
        Effect = "Allow"
        Resource = [
          "arn:${local.region_partition}:s3:::${aws_s3_bucket.billing_bucket.arn}"
        ]
        Principal = {
          AWS = "arn:${local.region_partition}:iam::${var.billing_principal}:root"
        }
        Action = [
          "s3:GetBucketAcl",
          "s3:GetBucketPolicy"
        ]
      },
      {
        Sid    = "BillingWrite20171206"
        Effect = "Allow"
        Resource = [
          "arn:${local.region_partition}:s3:::${aws_s3_bucket.billing_bucket.arn}/*"
        ]
        Principal = {
          AWS = "arn:${local.region_partition}:iam::${var.billing_principal}:root"
        }
        Action = [
          "s3:PutObject"
        ]
      }
    ]
  })
}
