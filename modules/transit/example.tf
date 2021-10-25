resource "aws_s3_bucket" "b" {

  bucket = var.logs_bucket
  acl    = "log-delivery-write"

  versioning {
    enabled = true
  }

}
