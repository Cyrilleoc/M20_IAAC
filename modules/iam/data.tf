data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

data "aws_iam_policy_document" "cap_account_policy" {
  statement {
    sid     = ""
    effect  = "Allow"
    actions = ["sts:AssumeRole"]

    principals {
      type        = "Principal"
      identifiers = ["arn:${local.region_partition}:iam::${local.cap_account}:root"]
    }
  }
}

# Minimize this code
data "aws_iam_policy_document" "geoaxis_saml_policy_gov" {
  statement {
    sid     = ""
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithSAML"]

    principals {
      type        = "Federated"
      identifiers = ["arn:${local.region_partition}:iam::${local.caller_account_id}:saml-provider/GEOAxIS"]
    }

    condition {
      test     = "StringEquals"
      variable = "SAML:aud"
      values   = [local.saml_url_gov]
      # below is as per cloudformation template
      # values   = ["https:https://signin.amazonaws-us-gov.com/saml"]
    }
  }
}

data "aws_iam_policy_document" "geoaxis_saml_policy" {
  statement {
    sid     = ""
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithSAML"]

    principals {
      type        = "Federated"
      identifiers = ["arn:${local.region_partition}:iam::${local.caller_account_id}:saml-provider/GEOAxIS"]
    }

    condition {
      test     = "StringEquals"
      variable = "SAML:aud"
      values   = [local.saml_url]
      # below is as per cloudformation template
      # values   = ["https:https://signin.amazonaws-us-gov.com/saml"]
    }
  }
}

data "aws_iam_policy_document" "geoaxis_saml_policy_sgov" {
  statement {
    sid     = ""
    effect  = "Allow"
    actions = ["sts:AssumeRoleWithSAML"]

    principals {
      type        = "Federated"
      identifiers = ["arn:${local.region_partition}:iam::${local.caller_account_id}:saml-provider/GEOAxIS"]
    }

    condition {
      test     = "StringEquals"
      variable = "SAML:aud"
      values   = [local.saml_url_sgov]
      # below is as per cloudformation template
      # values   = ["https:https://signin.amazonaws-us-gov.com/saml"]
    }
  }
}

