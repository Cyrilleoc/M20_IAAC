data "aws_iam_policy_document" "bastion_role_inline_policy" {
  statement {
    effect = "Allow"
    actions = [
      "ec2:DescribeAddresses",
      "ec2:AssociateAddress",
      "ec2:DisassociateAddress"
    ]
    resources = ["*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "s3:PutObject",
      "s3:PutObjectAcl"
    ]
    resources = ["arn:${var.region_partition}:s3:::${var.logs_bucket}/bastion-access-logs/*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "s3:GetObject"
    ]
    resources = ["arn:${var.region_partition}:s3:::${var.logs_bucket}/public-keys/*"]
  }

  statement {
    effect = "Allow"
    actions = [
      "s3:ListBucket"
    ]
    resources = ["arn:${var.region_partition}:s3:::${var.logs_bucket}"]
    condition {
      test     = "StringEquals"
      variable = "s3:prefix"
      values   = ["public-keys/"]
    }
  }

  statement {
    effect = "Allow"
    actions = [
      "s3:GetObject"
    ]
    resources = ["arn:${var.region_partition}:s3:::${var.config_bucket}/*"]
  }

}

data "aws_iam_policy_document" "transit_geoaxis_saml_policy" {
  statement {
    sid     = ""
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithSAML"]

    principals {
      type        = "Federated"
      identifiers = ["arn:${var.region_partition}:iam::${local.caller_account_id}:saml-provider/GEOAxIS"]
    }

    condition {
      test     = "StringEquals"
      variable = "SAML:aud"
      values   = [local.saml_map[replace(local.caller_aws_region, "-", "_")].saml]
    }
  }
}
