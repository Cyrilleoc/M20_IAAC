output "billing_bucket" {
  value = aws_s3_bucket.billing_bucket.bucket
}

output "logs_bucket" {
  value = var.logs_bucket
}

