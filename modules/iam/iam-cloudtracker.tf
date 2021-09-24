resource "aws_iam_policy" "ecloud_tracker_support_policy" {
  name        = "ECloudTrackerSupportPolicy"
  description = "Adds read permissions for support"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "ECloudTrackerSupportGenAccess"
        Action = [
          "support:DescribeAttachment",
          "support:DescribeCommunications",
          "support:DescribeTrustedAdvisorCheckRefreshStatuses",
          "support:DescribeCases",
          "support:DescribeIssueTypes",
          "support:DescribeSeverityLevels",
          "support:DescribeSupportLevel",
          "support:DescribeTrustedAdvisorCheckResult",
          "support:DescribeCaseAttributes",
          "support:DescribeServices",
          "support:DescribeTrustedAdvisorCheckSummaries",
          "support:DescribeTrustedAdvisorChecks"
        ]
        Effect   = "Allow"
        Resource = "*"
      }
    ]
  })
}

# resource "aws_iam_role" "ecloud_tracker_role" {
#   name                 = "E_CLOUDTRACKER"
#   max_session_duration = 43200

#   assume_role_policy = jsonencode({
#     Version = "2012-10-17"
#     Statement = [
#       {
#         Action = "sts:AssumeRole"
#         Effect = "Allow"
#         Sid    = ""
#         Principal = {
#           AWS = "arn:${local.region_partition}:iam::${var.cap_account}:root"
#         }
#       },
#     ]
#   })

#   depends_on = [
#     aws_iam_policy.ecloud_tracker_support_policy
#   ]
#   managed_policy_arns = ["arn:${local.region_partition}:iam::${local.caller_account_id}:policy/ServAdminPolicy"]
# }
