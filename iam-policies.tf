resource "aws_iam_policy" "serv_admin_policy" {
  name = "ServAdminPolicy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "ServAdminRoleManagedPolicy"
        Action = [
          "autoscaling:*",
          "aws-portal:View*",
          "budgets:ViewBudget",
          "config:Describe*",
          "config:Get*",
          "config:List*",
          "cloudformation:*",
          "cloudhsm:*",
          "cloudtrail:Describe*",
          "cloudtrail:Get*",
          "cloudtrail:Lookup*",
          "cloudwatch:*",
          "logs:*",
          "datapipeline:*",
          "directconnect:Describe*",
          "dynamodb:*",
          "ec2:AssociateDhcpOptions",
          "ec2:CreateDhcpOptions",
          "ec2:DeleteDhcpOptions",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:CreateSecurityGroup",
          "ec2:DeleteSecurityGroup",
          "ec2:DescribeSecurityGroups",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:AssignPrivateIpAddresses",
          "ec2:BundleInstance",
          "ec2:CancelBundleTask",
          "ec2:CancelConversionTask",
          "ec2:CancelExportTask",
          "ec2:CancelSpotInstanceRequests",
          "ec2:ConfirmProductInstance",
          "ec2:CreateInstanceExportTask",
          "ec2:CreateNetworkInterface",
          "ec2:CreatePlacementGroup",
          "ec2:CreateSpotDatafeedSubscription",
          "ec2:DeleteNetworkInterface",
          "ec2:DeletePlacementGroup",
          "ec2:DeleteSpotDatafeedSubscription",
          "ec2:DeregisterImage",
          "ec2:GetPasswordData",
          "ec2:ImportInstance",
          "ec2:ImportVolume",
          "ec2:RequestSpotInstances",
          "ec2:RunInstances",
          "ec2:UnassignPrivateIpAddresses",
          "ec2:ActivateLicense",
          "ec2:AllocateAddress",
          "ec2:AssociateAddress",
          "ec2:AttachNetworkInterface",
          "ec2:DeactivateLicense",
          "ec2:DetachNetworkInterface",
          "ec2:DisassociateAddress",
          "ec2:EnableVolumeIO",
          "ec2:ModifyInstanceAttribute",
          "ec2:ModifyNetworkInterfaceAttribute",
          "ec2:ModifySnapshotAttribute",
          "ec2:ModifyVolume*",
          "ec2:MonitorInstances",
          "ec2:RebootInstances",
          "ec2:ReleaseAddress",
          "ec2:ReportInstanceStatus",
          "ec2:ResetInstanceAttribute",
          "ec2:ResetNetworkInterfaceAttribute",
          "ec2:UnmonitorInstances",
          "ec2:CreateKeyPair",
          "ec2:DeleteKeyPair",
          "ec2:ImportKeyPair",
          "ec2:CreateImage",
          "ec2:CopyImage",
          "ec2:ModifyImageAttribute",
          "ec2:RegisterImage",
          "ec2:ResetImageAttribute",
          "ec2:AttachVolume",
          "ec2:CreateVolume",
          "ec2:DeleteVolume",
          "ec2:DetachVolume",
          "ec2:CopySnapshot",
          "ec2:CreateSnapshot",
          "ec2:CreateTags",
          "ec2:DeleteSnapshot",
          "ec2:DeleteTags",
          "ec2:ResetSnapshotAttribute",
          "ec2:StartInstances",
          "ec2:StopInstances",
          "ec2:DescribeInstanceStatus",
          "ec2:DescribeInstances",
          "ec2:TerminateInstances",
          "ec2:DescribeTags",
          "ec2:Describe*",
          "ec2:GetConsoleOutput",
          "ec2:ReplaceIamInstanceProfileAssociation",
          "ec2:DisassociateIamInstanceProfile",
          "ec2:AssociateIamInstanceProfile",
          "elasticache:*",
          "elasticloadbalancing:*",
          "elasticmapreduce:*",
          "elasticsearch:*",
          "glacier:*",
          "iam:CreateServiceLinkedRole",
          "iam:DeleteServerCertificate",
          "iam:DeleteSigningCertificate",
          "iam:UpdateServerCertificate",
          "iam:UpdateSigningCertificate",
          "iam:UploadServerCertificate",
          "iam:UploadSigningCertificate",
          "iam:GenerateCredentialReport",
          "iam:Get*",
          "iam:List*",
          "kinesis:*",
          "kms:Describe*",
          "kms:GetKeyPolicy",
          "kms:GetKeyRotationStatus",
          "kms:List*",
          "aws-marketplace:View*",
          "rds:*",
          "redshift:*",
          "s3:*",
          "sns:*",
          "sqs:*",
          "snowball:Describe*",
          "snowball:Get*",
          "snowball:List*",
          "sts:DecodeAuthorizationMessage",
          "sts:GetCallerIdentity",
          "support:*",
          "swf:*",
          "trustedadvisor:*",
          "workspaces:*",
          "dms:*",
          "ds:*",
          "states:*",
          "codedeploy:*",
          "lambda:*",
          "diode:*",
          "health:Describe*"
        ]
        Effect   = "Allow"
        Resource = "*"
      },
      {
        Sid = "ServAdminPassRolePolicy"
        Action = [
          "iam:PassRole"
        ]
        Effect   = "Allow"
        Resource = "*"
      },
      {
        Sid = "ServAdminPassRoleEMRPolicy"
        Action = [
          "iam:PassRole"
        ]
        Effect   = "Allow"
        Resource = "arn:${local.region_partition}:iam::*:role/EMRSERVICE"
      },
      {
        Sid = "ServAdminDenyPolicy"
        Action = [
          "elasticache:Purchase*",
          "kms:CreateGrant",
          "kms:RevokeGrant",
          "kms:CancelKeyDeletion",
          "kms:CreateAlias",
          "kms:CreateKey",
          "kms:Delete*",
          "kms:Disable*",
          "kms:Enable*",
          "kms:Put*",
          "kms:Update*",
          "kms:ScheduleKeyDeletion",
          "kms:Decrypt*",
          "kms:Encrypt*",
          "kms:Generate*",
          "kms:ReEncrypt*",
          "rds:Purchase*",
          "redshift:Purchase*", # new permissions after this line
          "dms:CreateReplicationSubnetGroup",
          "dms:DeleteReplicationSubnetGroup",
          "dms:ModifyReplicationSubnetGroup"
        ]
        Effect   = "Deny"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "clapper_policy" {
  name = "ClapperPolicy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "ClapperEC2Allow"
        Action = [
          "ec2:StartInstances",
          "ec2:StopInstances",
          "ec2:DescribeInstanceStatus",
          "ec2:DescribeInstances",
          "ec2:TerminateInstances",
          "ec2:CreateTags",
          "ec2:DeleteTags",
          "ec2:DescribeTags",
          "ec2:Describe*",
          "ec2:GetConsoleOutput",
          "iam:ListAccountAliases"
        ]
        Effect   = "Allow"
        Resource = "*"
      },
      {
        Sid = "ClapperKMSDenyGrants"
        Action = [
          "kms:CreateGrant",
          "kms:RevokeGrant"
        ]
        Effect   = "Deny"
        Resource = "*"
        # add condition here
        # Condition:
        #   Bool:
        #     'kms:GrantIsForAWSResource': 'false'
      },
      {
        Sid = "ServAdminPassRoleEMRPolicy"
        Action = [
          "iam:PassRole"
        ]
        Effect   = "Allow"
        Resource = "arn:${local.region_partition}:iam::*:role/EMRSERVICE"
      },
      {
        Sid = "ServAdminDenyPolicy"
        Action = [
          "elasticache:Purchase*",
          "kms:CreateGrant",
          "kms:RevokeGrant",
          "kms:CancelKeyDeletion",
          "kms:CreateAlias",
          "kms:CreateKey",
          "kms:Delete*",
          "kms:Disable*",
          "kms:Enable*",
          "kms:Put*",
          "kms:Update*",
          "kms:ScheduleKeyDeletion",
          "kms:Decrypt*",
          "kms:Encrypt*",
          "kms:Generate*",
          "kms:ReEncrypt*",
          "rds:Purchase*",
          "redshift:Purchase*", # new permissions after this line
          "dms:CreateReplicationSubnetGroup",
          "dms:DeleteReplicationSubnetGroup",
          "dms:ModifyReplicationSubnetGroup"
        ]
        Effect   = "Deny"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "net_admin_policy" {
  name = "NetAdminPolicy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "NetAdminNetManageAccess"
        Action = [
          "autoscaling:Describe*",
          "aws-portal:View*",
          "budgets:ViewBudget",
          "config:Describe*",
          "config:Get*",
          "config:List*",
          "cloudformation:*",
          "cloudhsm:Describe*",
          "cloudhsm:Get*",
          "cloudhsm:List*",
          "cloudtrail:Describe*",
          "cloudtrail:Get*",
          "cloudtrail:Lookup*",
          "cloudwatch:Describe*",
          "cloudwatch:Get*",
          "cloudwatch:List*",
          "logs:Describe*",
          "logs:Get*",
          "logs:Test*",
          "datapipeline:Describe*",
          "datapipeline:List*",
          "directconnect:*",
          "dynamodb:ListTables",
          "dynamodb:DescribeTable",
          "ec2:AcceptVpcPeeringConnection",
          "ec2:AssociateRouteTable",
          "ec2:AttachInternetGateway",
          "ec2:AttachVpnGateway",
          "ec2:CreateNetworkAcl",
          "ec2:CreateNetworkAclEntry",
          "ec2:CreateCustomerGateway",
          "ec2:CreateInternetGateway",
          "ec2:CreateRoute",
          "ec2:CreateRouteTable",
          "ec2:CreateSubnet",
          "ec2:CreateVpc",
          "ec2:CreateVpcEndpoint",
          "ec2:CreateVpcPeeringConnection",
          "ec2:CreateVpnConnection",
          "ec2:CreateVpnConnectionRoute",
          "ec2:CreateVpnGateway",
          "ec2:DeleteCustomerGateway",
          "ec2:DeleteInternetGateway",
          "ec2:DeleteNetworkAcl",
          "ec2:DeleteNetworkAclEntry",
          "ec2:DeleteRoute",
          "ec2:DeleteRouteTable",
          "ec2:DeleteSubnet",
          "ec2:DeleteVpc",
          "ec2:DeleteVpcEndpoints",
          "ec2:DeleteVpcPeeringConnection",
          "ec2:DeleteVpnConnection",
          "ec2:DeleteVpnConnectionRoute",
          "ec2:DeleteVpnGateway",
          "ec2:DetachInternetGateway",
          "ec2:DetachVpnGateway",
          "ec2:DisableVgwRoutePropagation",
          "ec2:DisassociateRouteTable",
          "ec2:EnableVgwRoutePropagation",
          "ec2:ModifySubnetAttribute",
          "ec2:ModifyVpcAttribute",
          "ec2:ModifyVpcEndpoint",
          "ec2:RejectVpcPeeringConnection",
          "ec2:ReplaceNetworkAclAssociation",
          "ec2:ReplaceNetworkAclEntry",
          "ec2:ReplaceRoute",
          "ec2:ReplaceRouteTableAssociation",
          "ec2:AssociateDhcpOptions",
          "ec2:CreateDhcpOptions",
          "ec2:DeleteDhcpOptions",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:CreateSecurityGroup",
          "ec2:DeleteSecurityGroup",
          "ec2:DescribeSecurityGroups",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:CreateTags",
          "ec2:DeleteTags",
          "ec2:DescribeTags",
          "ec2:Describe*",
          "ec2:GetConsoleOutput",
          "ec2:TerminateInstances",
          "elasticache:Describe*",
          "elasticache:List*",
          "elasticloadbalancing:Describe*",
          "elasticmapreduce:Describe*",
          "elasticmapreduce:List*",
          "glacier:Describe*",
          "glacier:Get*",
          "glacier:List*",
          "iam:CreateServiceLinkedRole",
          "iam:GenerateCredentialReport",
          "iam:Get*",
          "iam:List*",
          "kinesis:Describe*",
          "kinesis:List*",
          "kms:Describe*",
          "kms:GetKeyPolicy",
          "kms:GetKeyRotationStatus",
          "kms:List*",
          "aws-marketplace:View*",
          "rds:Describe*",
          "rds:List*",
          "redshift:Describe*",
          "redshift:List*",
          "sns:Get*",
          "sns:List*",
          "sqs:Get*",
          "sqs:List*",
          "snowball:Describe*",
          "snowball:Get*",
          "snowball:List*",
          "sts:DecodeAuthorizationMessage",
          "support:*",
          "swf:Count*",
          "swf:Describe*",
          "swf:Get*",
          "swf:List*",
          "trustedadvisor:Exclude*",
          "trustedadvisor:Include*",
          "trustedadvisor:Refresh*",
          "trustedadvisor:Describe*",
          "workspaces:AssociateIpGroups",
          "workspaces:AuthorizeIpRules",
          "workspaces:CreateIpGroup",
          "workspaces:DeleteIpGroup",
          "workspaces:Describe*",
          "workspaces:DisassociateIpGroups",
          "workspaces:List*",
          "workspaces:RevokeIpRules",
          "workspaces:UpdateRulesOfIpGroup",
          "dms:CreateReplicationSubnetGroup",
          "dms:DeleteReplicationSubnetGroup",
          "dms:Describe*",
          "dms:List*",
          "dms:ModifyEndpoint",
          "dms:ModifyReplicationSubnetGroup",
          "dms:TestConnection",
          "ds:AddIpRoutes",
          "ds:CreateLogSubscription",
          "ds:DeleteLogSubscription",
          "ds:Describe*",
          "ds:Get*",
          "ds:List*",
          "ds:RemoveIpRoutes",
          "states:Describe*",
          "states:Get*",
          "states:List*",
          "codedeploy:ContinueDeployment",
          "codedeploy:PutLifecycleEventHookExecutionStatus",
          "lambda:Get*",
          "lambda:List*",
          "health:Describe*",
          "diode:Describe*",
          "diode:Get*",
          "diode:List*"
        ]
        Effect   = "Allow"
        Resource = "*"
      },
      {
        Sid = "NetAdminRunInstances"
        Action = [
          "ec2:RunInstances"
        ]
        Effect = "Allow"
        Resource = [
          "arn:${local.region_partition}:ec2::*:*:instance/*",
          "arn:${local.region_partition}:ec2::*:*:image/*",
          "arn:${local.region_partition}:ec2::*:*:instance/*",
          "arn:${local.region_partition}:ec2::*:*:subnet/*",
          "arn:${local.region_partition}:ec2::*:*:network-interface/*",
          "arn:${local.region_partition}:ec2::*:*:volume/*",
          "arn:${local.region_partition}:ec2::*:*:key-pair/*",
          "arn:${local.region_partition}:ec2::*:*:security-group/*"
        ]
      },
      {
        Sid = "NetAdminS3TemplateAccess"
        Action = [
          "s3:*"
        ]
        Effect = "Allow"
        Resource = [
          "arn:${local.region_partition}:s3:::cf-templates*",
          "arn:${local.region_partition}:s3:::cf-templates*/*"
        ]
      },
      {
        Sid = "NetAdminKMSDeny"
        Action = [
          "kms:CreateGrant",
          "kms:RevokeGrant",
          "kms:CancelKeyDeletion",
          "kms:CreateAlias",
          "kms:CreateKey",
          "kms:Delete*",
          "kms:Disable*",
          "kms:Enable*",
          "kms:Put*",
          "kms:Update*",
          "kms:ScheduleKeyDeletion",
          "kms:Decrypt*",
          "kms:Encrypt*",
          "kms:Generate*",
          "kms:ReEncrypt*"
        ]
        Effect   = "Deny"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "prov_admin_policy" {
  name = "ProvAdminPolicy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "NetAdminNetManageAccess"
        Action = [
          "autoscaling:Describe*",
          "aws-portal:*",
          "budgets:ModifyBudget",
          "budgets:ViewBudget",
          "config:Describe*",
          "config:Get*",
          "config:List*",
          "cloudformation:*",
          "cloudhsm:Describe*",
          "cloudhsm:Get*",
          "cloudhsm:List*",
          "cloudtrail:Describe*",
          "cloudtrail:Get*",
          "cloudtrail:Lookup*",
          "cloudwatch:*",
          "logs:*",
          "datapipeline:Describe*",
          "datapipeline:List*",
          "directconnect:Describe*",
          "dynamodb:ListTables",
          "dynamodb:DescribeTable",
          "ec2:DescribeAccountAttributes",
          "ec2:DescribeAvailabilityZones",
          "ec2:DescribeReservedInstances",
          "ec2:DescribeReservedInstancesOfferings",
          "ec2:ModifyReservedInstances",
          "ec2:PurchaseReservedInstancesOffering",
          "ec2:Describe*",
          "ec2:GetConsoleOutput",
          "elasticache:Purchase*",
          "elasticache:DescribeReserved*",
          "elasticache:Describe*",
          "elasticache:List*",
          "elasticloadbalancing:Describe*",
          "elasticmapreduce:Describe*",
          "elasticmapreduce:List*",
          "glacier:Describe*",
          "glacier:Get*",
          "glacier:List*",
          "iam:*",
          "kinesis:Describe*",
          "kinesis:List*",
          "kms:Describe*",
          "kms:GetKeyPolicy",
          "kms:GetKeyRotationStatus",
          "kms:List*",
          "aws-marketplace:*",
          "rds:Purchase*",
          "rds:DescribeReserved*",
          "rds:Describe*",
          "rds:List*",
          "redshift:Purchase*",
          "redshift:DescribeReserved*",
          "redshift:Describe*",
          "redshift:List*",
          "s3:GetBucket*",
          "s3:GetLifecycle*",
          "s3:GetObjectAcl",
          "s3:GetObjectVersionAcl",
          "s3:List*",
          "sns:*",
          "sqs:Get*",
          "sqs:List*",
          "snowball:Describe*",
          "snowball:Get*",
          "snowball:List*",
          "sts:DecodeAuthorizationMessage",
          "support:*",
          "swf:Count*",
          "swf:Describe*",
          "swf:Get*",
          "swf:List*",
          "trustedadvisor:*",
          "workspaces:Describe*",
          "workspaces:List*",
          "dms:Describe*",
          "dms:List*",
          "ds:Describe*",
          "ds:Get*",
          "ds:List*",
          "states:Describe*",
          "states:Get*",
          "states:List*",
          "states:Send*",
          "states:StartExecution",
          "states:StopExecution",
          "states:UpdateStateMachine",
          "codedeploy:BatchGet*",
          "codedeploy:Get*",
          "codedeploy:List*",
          "lambda:Get*",
          "lambda:List*",
          "health:Describe*",
          "diode:Describe*",
          "diode:Get*",
          "diode:List*"
        ]
        Effect   = "Allow"
        Resource = "*"
      },
      {
        Sid = "ProvAdminS3Access"
        Action = [
          "s3:CreateBucket",
          "s3:DeleteBucketPolicy",
          "s3:PutBucketAcl",
          "s3:PutBucketLogging",
          "s3:PutBucketNotification",
          "s3:PutBucketPolicy",
          "s3:PutBucketTagging",
          "s3:PutBucketVersioning",
          "s3:Get*",
          "s3:List*"
        ]
        Effect = "Allow"
        Resource = [
          "arn:${local.region_partition}:s3:::*billing*",
          "arn:${local.region_partition}:s3:::*billing*/*"
        ]
      },
      {
        Sid = "ProvAdminS3FullAccess"
        Action = [
          "s3:*"
        ]
        Effect = "Allow"
        Resource = [
          "arn:${local.region_partition}:s3:::cf-templates*",
          "arn:${local.region_partition}:s3:::cf-templates*/*"
        ]
      },
      {
        Sid = "ProvAdminS3GetTrailsAccess"
        Action = [
          "s3:*",
          "s3:List*"
        ]
        Effect = "Allow"
        Resource = [
          "arn:${local.region_partition}:s3:::*cloudtrail*",
          "arn:${local.region_partition}:s3:::*cloudtrail*/*"
        ]
      },
      {
        Sid = "ProvAdminS3GetLogsAccess"
        Action = [
          "s3:*",
          "s3:List*"
        ]
        Effect = "Allow"
        Resource = [
          "arn:${local.region_partition}:s3:::*bucketlogs*",
          "arn:${local.region_partition}:s3:::*bucketlogs*/*"
        ]
      },
      {
        Sid = "ProvAdminKMSAccess"
        Action = [
          "kms:CreateGrant",
          "kms:RevokeGrant",
          "kms:CancelKeyDeletion",
          "kms:CreateAlias",
          "kms:CreateKey",
          "kms:Delete*",
          "kms:Disable*",
          "kms:Enable*",
          "kms:Put*",
          "kms:Update*",
          "kms:ScheduleKeyDeletion",
          "kms:Decrypt*",
          "kms:Encrypt*",
          "kms:Generate*",
          "kms:ReEncrypt*"
        ]
        Effect   = "Deny"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_policy" "CNDIS_policy" {
  name = "CNDISPolicy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow",
        Resource = "*",
        Sid      = "CNDISGenAccess"
        Action = [
          "autoscaling:Describe*",
          "aws-portal:View*",
          "budgets:ViewBudget",
          "config:Describe*",
          "config:Get*",
          "config:List*",
          "cloudformation:*",
          "cloudhsm:Describe*",
          "cloudhsm:Get*",
          "cloudhsm:List*",
          "cloudtrail:Describe*",
          "cloudtrail:Get*",
          "cloudtrail:Lookup*",
          "cloudwatch:*",
          "logs:*",
          "datapipeline:Describe*",
          "datapipeline:List*",
          "directconnect:Describe*",
          "dynamodb:ListTables",
          "dynamodb:DescribeTable",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:CreateSecurityGroup",
          "ec2:DeleteSecurityGroup",
          "ec2:DescribeSecurityGroups",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:Describe*",
          "ec2:GetConsoleOutput",
          "elasticache:Describe*",
          "elasticache:List*",
          "elasticloadbalancing:Describe*",
          "elasticmapreduce:Describe*",
          "elasticmapreduce:List*",
          "glacier:Describe*",
          "glacier:Get*",
          "glacier:List*",
          "iam:GenerateCredentialReport",
          "iam:Get*",
          "iam:List*",
          "kinesis:Describe*",
          "kinesis:List*",
          "kms:Describe*",
          "kms:GetKeyPolicy",
          "kms:GetKeyRotationStatus",
          "kms:List*",
          "aws-marketplace:View*",
          "rds:Describe*",
          "rds:List*",
          "redshift:Describe*",
          "redshift:List*",
          "s3:CreateBucket",
          "s3:GetBucket*",
          "s3:GetLifecycle*",
          "s3:GetObject",
          "s3:GetObjectAcl",
          "s3:GetObjectVersionAcl",
          "s3:List*",
          "s3:PutObject",
          "sts:DecodeAuthorizationMessage",
          "support:*",
          "swf:Count*",
          "swf:Describe*",
          "swf:Get*",
          "swf:List*",
          "trustedadvisor:*",
          "workspaces:Describe*",
          "workspaces:List*",
          "dms:Describe*",
          "dms:List*",
          "ds:Describe*",
          "ds:Get*",
          "ds:List*",
          "states:Describe*",
          "states:Get*",
          "states:List*",
          "codedeploy:BatchGet*",
          "codedeploy:Get*",
          "codedeploy:List*",
          "lambda:Get*",
          "lambda:List*",
          "health:Describe*",
          "diode:Describe*",
          "diode:Get*",
          "diode:List*"
        ]
      },
      {
        Effect   = "Allow",
        Resource = "arn:${local.region_partition}:iam::*:user/cloudtrail",
        Sid      = "CNDISIAMAccess"
        Action = [
          "iam:CreateAccessKey",
          "iam:CreateLoginProfile",
          "iam:DeleteAccessKey",
          "iam:DeleteLoginProfile",
          "iam:UpdateAccessKey",
          "iam:UpdateLoginProfile"
        ]
      },
      {
        Effect = "Allow",
        Resource = [
          "arn:${local.region_partition}:s3:::cf-templates*",
          "arn:${local.region_partition}:s3:::cf-templates*/*",
        ]
        Sid = "CNDISS3FullAccess"
        Action = [
          "s3:*"
        ]
      },
      {
        Effect = "Allow",
        Resource = [
          "arn:${local.region_partition}:s3:::*cloudtrail*",
          "arn:${local.region_partition}:s3:::*cloudtrail*/*",
        ]
        Sid = "CNDISS3CloudTrailReadAccess"
        Action = [
          "s3:Get*",
          "s3:List*"
        ]
      },
      {
        Effect = "Allow",
        Resource = [
          "arn:${local.region_partition}:s3:::*bucketlogs*",
          "arn:${local.region_partition}:s3:::*bucketlogs*/*",
        ]
        Sid = "CNDISS3LogReadAccess"
        Action = [
          "s3:Get*",
          "s3:List*"
        ]
      },
      {
        Effect = "Allow",
        Resource = [
          "arn:${local.region_partition}:sns:us-iso-east-1:*:cloudtrail"
        ]
        Sid = "CNDISSNSFullAccess"
        Action = [
          "sns:*"
        ]
      },
      {
        Effect = "Allow",
        Resource = [
          "arn:${local.region_partition}:sns:us-iso-east-1:*:cloudtrail"
        ]
        Sid = "CNDISSQSFullAccess"
        Action = [
          "sqs:*"
        ]
      },
      {
        Effect   = "Deny",
        Resource = "*"
        Sid      = "CNDISMKSDeny"
        Action = [
          "kms:CreateGrant",
          "kms:RevokeGrant",
          "kms:CancelKeyDeletion",
          "kms:CreateAlias",
          "kms:CreateKey",
          "kms:Delete*",
          "kms:Disable*",
          "kms:Enable*",
          "kms:Put*",
          "kms:Update*",
          "kms:ScheduleKeyDeletion",
          "kms:Decrypt*",
          "kms:Encrypt*",
          "kms:Generate*",
          "kms:ReEncrypt*"
        ]
      }
    ]
  })
}

resource "aws_iam_policy" "CNDIS_readonly_policy" {
  name = "CNDISReadOnlyPolicy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect" = "Allow",
        "Sid"    = "CNDISReadOnlyGen",
        "Action" = [
          "autoscaling:Describe*",
          "aws-portal:View*",
          "budgets:ViewBudget",
          "config:Describe*",
          "config:Get*",
          "config:List*",
          "cloudformation:Describe*",
          "cloudformation:EstimateTemplateCost",
          "cloudformation:Get*",
          "cloudformation:List*",
          "cloudformation:PreviewStackUpdate",
          "cloudformation:ValidateTemplate",
          "cloudhsm:Describe*",
          "cloudhsm:Get*",
          "cloudhsm:List*",
          "cloudtrail:Describe*",
          "cloudtrail:Get*",
          "cloudtrail:Lookup*",
          "cloudwatch:Describe*",
          "cloudwatch:Get*",
          "cloudwatch:List*",
          "logs:Describe*",
          "logs:Get*",
          "logs:Test*",
          "datapipeline:Describe*",
          "datapipeline:List*",
          "directconnect:Describe*",
          "dynamodb:ListTables",
          "dynamodb:DescribeTable",
          "ec2:Describe*",
          "ec2:GetConsoleOutput",
          "elasticache:Describe*",
          "elasticache:List*",
          "elasticloadbalancing:Describe*",
          "elasticmapreduce:Describe*",
          "elasticmapreduce:List*",
          "glacier:Describe*",
          "glacier:Get*",
          "glacier:List*",
          "iam:GenerateCredentialReport",
          "iam:Get*",
          "iam:List*",
          "kinesis:Describe*",
          "kinesis:List*",
          "kms:Describe*",
          "kms:GetKeyPolicy",
          "kms:GetKeyRotationStatus",
          "kms:List*",
          "aws-marketplace:View*",
          "rds:Describe*",
          "rds:List*",
          "redshift:Describe*",
          "redshift:List*",
          "s3:GetBucket*",
          "s3:GetLifecycle*",
          "s3:GetObjectAcl",
          "s3:GetObjectVersionAcl",
          "s3:List*",
          "sns:Get*",
          "sns:List*",
          "sqs:Get*",
          "sqs:List*",
          "snowball:Describe*",
          "snowball:Get*",
          "snowball:List*",
          "swf:Count*",
          "swf:Describe*",
          "swf:Get*",
          "swf:List*",
          "trustedadvisor:*"
        ],
        "Resource" = "*"
      },
      {
        "Effect" = "Allow",
        "Sid"    = "CNDISReadOnlyS3",
        "Action" = [
          "s3:Get*",
          "s3:List*"
        ],
        "Resource" = [
          "arn:${local.region_partition}:s3:::*billing*",
          "arn:${local.region_partition}:s3:::*billing*/*"
        ]
      },
      {
        "Effect" = "Deny",
        "Sid"    = "CNDISReadOnlyKMSDeny",
        "Action" = [
          "kms:CreateGrant",
          "kms:RevokeGrant",
          "kms:CancelKeyDeletion",
          "kms:CreateAlias",
          "kms:CreateKey",
          "kms:Delete*",
          "kms:Disable*",
          "kms:Enable*",
          "kms:Put*",
          "kms:Update*",
          "kms:ScheduleKeyDeletion",
          "kms:Decrypt*",
          "kms:Encrypt*",
          "kms:Generate*",
          "kms:ReEncrypt*"
        ],
        "Resource" = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "marketplace_policy" {
  name        = "MarketplacePolicy"
  description = "Managed policy for MarketplaceRole permissions."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect" = "Allow",
        "Sid"    = "MarketplaceFullAccess",
        "Action" = [
          "aws-marketplace:*"
        ],
        "Resource" = "*"
      },
      {
        "Effect" = "Deny",
        "Sid"    = "MarketplaceKMSDeny",
        "Action" = [
          "kms:CreateGrant",
          "kms:RevokeGrant",
          "kms:CancelKeyDeletion",
          "kms:CreateAlias",
          "kms:CreateKey",
          "kms:Delete*",
          "kms:Disable*",
          "kms:Enable*",
          "kms:Put*",
          "kms:Update*",
          "kms:ScheduleKeyDeletion",
          "kms:Decrypt*",
          "kms:Encrypt*",
          "kms:Generate*",
          "kms:ReEncrypt*"
        ],
        "Resource" = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "business_policy" {
  name        = "BusinessPolicy"
  description = "Managed policy for BusinessRole permissions."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect" = "Allow",
        "Sid"    = "BusinessGenAccess",
        "Action" = [
          "aws-portal:ModifyBilling",
          "aws-portal:ModifyPaymentMethods",
          "aws-portal:View*",
          "budgets:ModifyBudget",
          "budgets:ViewBudget",
          "cloudwatch:*",
          "ec2:DescribeAccountAttributes",
          "ec2:DescribeAvailabilityZones",
          "ec2:*ReservedInstances*",
          "elasticache:Purchase*",
          "elasticache:DescribeReserved*",
          "aws-marketplace:View*",
          "rds:Purchase*",
          "rds:DescribeReserved*",
          "redshift:Purchase*",
          "redshift:DescribeReserved*",
          "s3:ListAllMyBuckets",
          "sns:Get*",
          "sns:List*",
          "support:*"
        ],
        "Resource" = "*"
      },
      {
        "Effect" = "Allow",
        "Sid"    = "BusinessS3ReadAccess",
        "Action" = [
          "s3:Get*",
          "s3:List*"
        ],
        "Resource" = [
          "arn:${local.region_partition}:s3:::*billing*",
          "arn:${local.region_partition}:s3:::*billing*/*"
        ]
      },
      {
        "Effect" = "Allow",
        "Sid"    = "BusinessSNSFullAccess",
        "Action" = [
          "sns:*"
        ],
        "Resource" = [
          "arn:${local.region_partition}:sns:*:*:aws_budget*"
        ]
      },
      {
        "Effect" = "Allow",
        "Sid"    = "BusinessTrustedAdvisorAccess",
        "Action" = [
          "trustedadvisor:Exclude*",
          "trustedadvisor:Include*",
          "trustedadvisor:Refresh*",
          "trustedadvisor:Describe*"
        ],
        "Resource" = [
          "arn:${local.region_partition}:trustedadvisor:*:*:checks/cost_optimizing/*"
        ]
      },
      {
        "Effect" = "Deny",
        "Sid"    = "BusinessKMSDeny",
        "Action" = [
          "kms:CreateGrant",
          "kms:RevokeGrant",
          "kms:CancelKeyDeletion",
          "kms:CreateAlias",
          "kms:CreateKey",
          "kms:Delete*",
          "kms:Disable*",
          "kms:Enable*",
          "kms:Put*",
          "kms:Update*",
          "kms:ScheduleKeyDeletion",
          "kms:Decrypt*",
          "kms:Encrypt*",
          "kms:Generate*",
          "kms:ReEncrypt*",
        ],
        "Resource" = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "tech_readonly_policy" {
  name        = "TechReadOnlyPolicy"
  description = "Maanaged policy for TechReadOnlyRole permissions."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect" = "Allow",
        "Sid"    = "TechReadOnlyAccess",
        "Action" = [
          "autoscaling:Describe*",
          "aws-portal:View*",
          "budgets:ViewBudget",
          "config:Describe*",
          "config:Get*",
          "config:List*",
          "cloudformation:Describe*",
          "cloudformation:EstimateTemplateCost",
          "cloudformation:Get*",
          "cloudformation:List*",
          "cloudformation:PreviewStackUpdate",
          "cloudformation:ValidateTemplate",
          "cloudhsm:Describe*",
          "cloudhsm:Get*",
          "cloudhsm:List*",
          "cloudtrail:Describe*",
          "cloudtrail:Get*",
          "cloudtrail:Lookup*",
          "cloudwatch:Describe*",
          "cloudwatch:Get*",
          "cloudwatch:List*",
          "logs:Describe*",
          "logs:Get*",
          "logs:Test*",
          "datapipeline:Describe*",
          "datapipeline:List*",
          "directconnect:Describe*",
          "dynamodb:ListTables",
          "dynamodb:DescribeTable",
          "ec2:Describe*",
          "ec2:GetConsoleOutput",
          "elasticache:Describe*",
          "elasticache:List*",
          "elasticloadbalancing:Describe*",
          "elasticmapreduce:Describe*",
          "elasticmapreduce:List*",
          "glacier:Describe*",
          "glacier:Get*",
          "glacier:List*",
          "iam:GenerateCredentialReport",
          "iam:Get*",
          "iam:List*",
          "kinesis:Describe*",
          "kinesis:List*",
          "kms:Describe*",
          "kms:GetKeyPolicy",
          "kms:GetKeyRotationStatus",
          "kms:List*",
          "aws-marketplace:View*",
          "rds:Describe*",
          "rds:List*",
          "redshift:Describe*",
          "redshift:List*",
          "s3:GetBucket*",
          "s3:GetLifecycle*",
          "s3:GetObjectAcl",
          "s3:GetObjectVersionAcl",
          "s3:List*",
          "sns:Get*",
          "sns:List*",
          "sqs:Get*",
          "sqs:List*",
          "snowball:Describe*",
          "snowball:Get*",
          "snowball:List*",
          "swf:Count*",
          "swf:Describe*",
          "swf:Get*",
          "swf:List*",
          "workspaces:Describe*",
          "workspaces:List*",
          "dms:Describe*",
          "dms:List*",
          "ds:Describe*",
          "ds:List*",
          "states:Describe*",
          "states:List*",
          "codedeploy:List*",
          "lambda:List*",
          "health:Describe*",
          "diode:Describe*",
          "diode:List*"
        ],
        "Resource" = "*"
      },
      {
        "Effect" = "Allow",
        "Sid"    = "TechReadOnlyS3Access",
        "Action" = [
          "s3:Get*",
          "s3:List*"
        ],
        "Resource" = [
          "arn:${local.region_partition}:s3:::*billing*",
          "arn:${local.region_partition}:s3:::*billing*/*"
        ]
      },
      {
        "Effect" = "Allow",
        "Sid"    = "TechReadOnlyTrustedAdvisorCostAccess",
        "Action" = [
          "trustedadvisor:Exclude*",
          "trustedadvisor:Include*",
          "trustedadvisor:Refresh*",
          "trustedadvisor:Describe*"
        ],
        "Resource" = [
          "arn:${local.region_partition}:trustedadvisor:*:*:checks/cost_optimizing/*"
        ]
      },
      {
        "Effect" = "Allow",
        "Sid"    = "TechReadOnlyTrustedAdvisorChecksAccess",
        "Action" = [
          "trustedadvisor:Exclude*",
          "trustedadvisor:Include*",
          "trustedadvisor:Refresh*",
          "trustedadvisor:Describe*"
        ],
        "Resource" = [
          "arn:${local.region_partition}:trustedadvisor:*:*:checks/performance/*"
        ]
      },
      {
        "Effect" = "Allow",
        "Sid"    = "TechReadOnlyTrustedAdvisorFaultToleranceAccess",
        "Action" = [
          "trustedadvisor:Exclude*",
          "trustedadvisor:Include*",
          "trustedadvisor:Refresh*",
          "trustedadvisor:Describe*"
        ],
        "Resource" = [
          "arn:${local.region_partition}:trustedadvisor:*:*:checks/fault_tolerance/*"
        ]
      },
      {
        "Effect" = "Deny",
        "Sid"    = "TechReadOnlyKMSDeny",
        "Action" = [
          "kms:CreateGrant",
          "kms:RevokeGrant",
          "kms:CancelKeyDeletion",
          "kms:CreateAlias",
          "kms:CreateKey",
          "kms:Delete*",
          "kms:Disable*",
          "kms:Enable*",
          "kms:Put*",
          "kms:Update*",
          "kms:ScheduleKeyDeletion",
          "kms:Decrypt*",
          "kms:Encrypt*",
          "kms:Generate*",
          "kms:ReEncrypt*"
        ],
        "Resource" = "*"
      },
    ]
  })
}

resource "aws_iam_policy" "proj_admin_policy" {
  name        = "ProjAdminPolicy"
  description = "Managed policy for ProjAdminRole permissions."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect" = "Action",
        "Sid"    = "ProjAdminGenAccess",
        "Action" = [
          "autoscaling:*",
          "aws-portal:View*",
          "budgets:ViewBudget",
          "config:Describe*",
          "config:Get*",
          "config:List*",
          "cloudformation:*",
          "cloudhsm:*",
          "cloudtrail:Describe*",
          "cloudtrail:Get*",
          "cloudtrail:Lookup*",
          "cloudwatch:*",
          "logs:*",
          "datapipeline:*",
          "directconnect:Describe*",
          "dynamodb:*",
          "ec2:CreateSubnet",
          "ec2:DeleteSubnet",
          "ec2:AssociateSubnet",
          "ec2:ModifySubnetAttribute",
          "ec2:AssociateDhcpOptions",
          "ec2:CreateDhcpOptions",
          "ec2:DeleteDhcpOptions",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:CreateSecurityGroup",
          "ec2:DeleteSecurityGroup",
          "ec2:DescribeSecurityGroups",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:AssignPrivateIpAddresses",
          "ec2:BundleInstance",
          "ec2:CancelBundleTask",
          "ec2:CancelConversionTask",
          "ec2:CancelExportTask",
          "ec2:CancelSpotInstanceRequests",
          "ec2:ConfirmProductInstance",
          "ec2:CreateInstanceExportTask",
          "ec2:CreateNetworkInterface",
          "ec2:CreatePlacementGroup",
          "ec2:CreateSpotDatafeedSubscription",
          "ec2:DeleteNetworkInterface",
          "ec2:DeletePlacementGroup",
          "ec2:DeleteSpotDatafeedSubscription",
          "ec2:DeregisterImage",
          "ec2:EnableEbsEncryptionByDefault",
          "ec2:Get*",
          "ec2:ImportInstance",
          "ec2:ImportVolume",
          "ec2:RequestSpotInstances",
          "ec2:RunInstances",
          "ec2:UnassignPrivateIpAddresses",
          "ec2:ActivateLicense",
          "ec2:AllocateAddress",
          "ec2:AssociateAddress",
          "ec2:AttachNetworkInterface",
          "ec2:DeactivateLicense",
          "ec2:DetachNetworkInterface",
          "ec2:DisassociateAddress",
          "ec2:EnableVolumeIO",
          "ec2:ModifyInstanceAttribute",
          "ec2:ModifyNetworkInterfaceAttribute",
          "ec2:ModifySnapshotAttribute",
          "ec2:ModifyVolume*",
          "ec2:MonitorInstances",
          "ec2:RebootInstances",
          "ec2:ReleaseAddress",
          "ec2:ReportInstanceStatus",
          "ec2:ResetInstanceAttribute",
          "ec2:ResetNetworkInterfaceAttribute",
          "ec2:UnmonitorInstances",
          "ec2:CreateKeyPair",
          "ec2:DeleteKeyPair",
          "ec2:ImportKeyPair",
          "ec2:AttachVolume",
          "ec2:CreateVolume",
          "ec2:DeleteVolume",
          "ec2:DetachVolume",
          "ec2:EnableVolumeIO",
          "ec2:ImportVolume",
          "ec2:ModifyVolumeAttribute",
          "ec2:ReportInstanceStatus",
          "ec2:ResetInstanceAttribute",
          "ec2:CopySnapshot",
          "ec2:CreateSnapshot*",
          "ec2:CreateTags",
          "ec2:CreateVolume",
          "ec2:DeleteSnapshot*",
          "ec2:DeleteTags",
          "ec2:DeleteVolume",
          "ec2:DetachVolume",
          "ec2:ModifySnapshotAttribute",
          "ec2:ModifyVolumeAttribute",
          "ec2:ReportInstanceStatus",
          "ec2:ResetInstanceAttribute",
          "ec2:ResetSnapshotAttribute",
          "ec2:StartInstances",
          "ec2:StopInstances",
          "ec2:DescribeInstanceStatus",
          "ec2:DescribeInstances",
          "ec2:TerminateInstances",
          "ec2:CreateTags",
          "ec2:DeleteTags",
          "ec2:DescribeTags",
          "ec2:Describe*",
          "ec2:GetConsoleOutput",
          "ec2:ReplaceIamInstanceProfileAssociation",
          "ec2:DisassociateIamInstanceProfile",
          "ec2:AssociateIamInstanceProfile",
          "ec2:CopyImage",
          "ec2:CreateImage",
          "ec2:ImportImage",
          "ec2:ModifyImageAttribute",
          "ec2:RegisterImage",
          "ec2:ResetImageAttribute",
          "ec2:CreateNatGateway",
          "ec2:ImportImage",
          "ec2:ImportSnapshot*",
          "ec2:CancelImportTask",
          "ec2:DescribeLaunchTemplates",
          "ec2:DescribeLaunchTemplateVersions",
          "ec2:GetLaunchTemplateData",
          "ec2:CreateLaunchTemplate",
          "ec2:CreateLaunchTemplateVersion",
          "ec2:DeleteLaunchTemplate",
          "ec2:DeleteLaunchTemplateVersions",
          "ec2:ModifyLaunchTemplate",
          "ec2messages:*",
          "elasticache:*",
          "elasticloadbalancing:*",
          "elasticmapreduce:*",
          "es:*",
          "glacier:*",
          "iam:CreateServiceLinkedRole",
          "iam:DeleteServerCertificate",
          "iam:DeleteSigningCertificate",
          "iam:UpdateServerCertificate",
          "iam:UpdateSigningCertificate",
          "iam:UploadServerCertificate",
          "iam:UploadSigningCertificate",
          "iam:GenerateCredentialReport",
          "iam:Get*",
          "iam:List*",
          "kinesis:*",
          "kms:*",
          "license-manager:*",
          "aws-marketplace:View*",
          "rds:*",
          "redshift:*",
          "s3:*",
          "sns:*",
          "sqs:*",
          "snowball:*",
          "ssm:*",
          "ssmmessages:*",
          "sts:DecodeAuthorizationMessage",
          "sts:GetCallerIdentity",
          "support:*",
          "swf:*",
          "trustedadvisor:*",
          "workspaces:*",
          "dms:*",
          "ds:*",
          "states:*",
          "codedeploy:*",
          "lambda:*",
          "health:Describe*",
          "diode:Describe*",
          "diode:Get*",
          "diode:List*",
          "ecs:*",
          "ecr:*",
          "sagemaker:*",
          "events:*",
          "apigateway:*",
          "route53:*"
        ]
        "Resource" = "*"
      },
      {
        "Effect" = "Allow",
        "Sid"    = "ProjAdminGenPassRole",
        "Action" = [
          "iam:PassRole"
        ],
        "Resource" = [
          "arn:${local.region_partition}:iam::*:role/INSTANCE*",
          "arn:${local.region_partition}:iam::*:role/LAMBDA*",
          "arn:${local.region_partition}:iam::*:role/snowball*",
          "arn:${local.region_partition}:iam::*:role/AFC2S*",
          "arn:${local.region_partition}:iam::*:role/workspaces*",
          "arn:${local.region_partition}:iam::*:role/service-role/*"
        ]
      },
      {
        "Effect" = "Allow",
        "Sid"    = "ProjAdminEMRPassRole",
        "Action" = [
          "iam:PassRole"
        ],
        "Resource" = [
          "arn:${local.region_partition}:iam::*:role/EMRSERVICE"
        ]
      },
      {
        "Effect" = "Deny",
        "Sid"    = "ProjAdminKMSECPurchaseDeny",
        "Action" = [
          "elasticache:Purchase*",
          "rds:Purchase*",
          "redshift:Purchase*"
        ],
        "Resource" = "*"
      },
      {
        "Effect" = "Deny",
        "Sid"    = "ProjAdminKMSGrantDeny",
        "Action" = [
          "ecs:DeleteAccountSetting"
        ],
        "Resource" = "*"
      },
      {
        "Effect" = "Allow",
        "Sid"    = "ProjAdminCreateAnyPolicy",
        "Action" = [
          "iam:CreatePolicy"
        ],
        "Resource" = "*"
      },
      {
        "Effect" = "Allow",
        "Sid"    = "ProjAdminCreateServiceRoles",
        "Action" = [
          "iam:AttachRolePolicy",
          "iam:CreateRole",
          "iam:PutRolePolicy"
        ],
        "Resource" = [
          "arn:${local.region_partition}:iam::${local.caller_account_id}:role/service-role/*"
        ]
      }
    ]
  })
}

resource "aws_iam_policy" "dev_admin_policy" {
  name        = "DevAdminPolicy"
  description = "Managed policy for DevAdminRole permissions."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect" = "Allow",
        "Sid"    = "DevAdminGenAccess",
        "Action" = [
          "autoscaling:*",
          "aws-portal:View*",
          "budgets:ViewBudget",
          "config:Describe*",
          "config:Get*",
          "config:List*",
          "cloudformation:*",
          "cloudhsm:*",
          "cloudtrail:Describe*",
          "cloudtrail:Get*",
          "cloudtrail:Lookup*",
          "cloudwatch:*",
          "logs:*",
          "datapipeline:*",
          "directconnect:Describe*",
          "dynamodb:*",
          "ec2:AssignPrivateIpAddresses",
          "ec2:BundleInstance",
          "ec2:CancelBundleTask",
          "ec2:CancelConversionTask",
          "ec2:CancelExportTask",
          "ec2:CancelSpotInstanceRequests",
          "ec2:ConfirmProductInstance",
          "ec2:CreateInstanceExportTask",
          "ec2:CreateNetworkInterface",
          "ec2:CreatePlacementGroup",
          "ec2:CreateSpotDatafeedSubscription",
          "ec2:DeleteNetworkInterface",
          "ec2:DeletePlacementGroup",
          "ec2:DeleteSpotDatafeedSubscription",
          "ec2:DeregisterImage",
          "ec2:GetPasswordData",
          "ec2:ImportInstance",
          "ec2:ImportVolume",
          "ec2:RequestSpotInstances",
          "ec2:RunInstances",
          "ec2:UnassignPrivateIpAddresses",
          "ec2:ActivateLicense",
          "ec2:AllocateAddress",
          "ec2:AssociateAddress",
          "ec2:AttachNetworkInterface",
          "ec2:DeactivateLicense",
          "ec2:DetachNetworkInterface",
          "ec2:DisassociateAddress",
          "ec2:EnableVolumeIO",
          "ec2:ModifyInstanceAttribute",
          "ec2:ModifyNetworkInterfaceAttribute",
          "ec2:ModifySnapshotAttribute",
          "ec2:ModifyVolume*",
          "ec2:MonitorInstances",
          "ec2:RebootInstances",
          "ec2:ReleaseAddress",
          "ec2:ReportInstanceStatus",
          "ec2:ResetInstanceAttribute",
          "ec2:ResetNetworkInterfaceAttribute",
          "ec2:UnmonitorInstances",
          "ec2:AttachVolume",
          "ec2:CreateVolume",
          "ec2:DeleteVolume",
          "ec2:DetachVolume",
          "ec2:EnableVolumeIO",
          "ec2:ImportVolume",
          "ec2:ModifyVolumeAttribute",
          "ec2:ReportInstanceStatus",
          "ec2:ResetInstanceAttribute",
          "ec2:CopySnapshot",
          "ec2:CreateSnapshot",
          "ec2:CreateTags",
          "ec2:CreateVolume",
          "ec2:DeleteSnapshot",
          "ec2:DeleteTags",
          "ec2:DeleteVolume",
          "ec2:DetachVolume",
          "ec2:ModifySnapshotAttribute",
          "ec2:ModifyVolumeAttribute",
          "ec2:ReportInstanceStatus",
          "ec2:ResetInstanceAttribute",
          "ec2:ResetSnapshotAttribute",
          "ec2:StartInstances",
          "ec2:StopInstances",
          "ec2:DescribeInstanceStatus",
          "ec2:DescribeInstances",
          "ec2:TerminateInstances",
          "ec2:CreateTags",
          "ec2:DeleteTags",
          "ec2:DescribeTags",
          "ec2:Describe*",
          "ec2:GetConsoleOutput",
          "elasticache:*",
          "elasticloadbalancing:*",
          "elasticmapreduce:*",
          "glacier:*",
          "iam:CreateServiceLinkedRole",
          "iam:DeleteServerCertificate",
          "iam:DeleteSigningCertificate",
          "iam:UpdateServerCertificate",
          "iam:UpdateSigningCertificate",
          "iam:UploadServerCertificate",
          "iam:UploadSigningCertificate",
          "iam:GenerateCredentialReport",
          "iam:Get*",
          "iam:List*",
          "kinesis:*",
          "kms:Describe*",
          "kms:GetKeyPolicy",
          "kms:GetKeyRotationStatus",
          "kms:List*",
          "aws-marketplace:View*",
          "rds:*",
          "redshift:*",
          "s3:*",
          "sns:*",
          "sqs:*",
          "sts:DecodeAuthorizationMessage",
          "support:*",
          "swf:*",
          "trustedadvisor:*",
          "workspaces:Describe*",
          "workspaces:List*",
          "dms:Describe*",
          "dms:List*",
          "ds:Describe*",
          "ds:Get*",
          "ds:List*",
          "states:*",
          "codedeploy:*",
          "lambda:*",
          "health:Describe*",
          "diode:Describe*",
          "diode:Get*",
          "diode:List*"
        ],
        "Resource" = "*"
      },
      {
        "Effect" = "Allow",
        "Sid"    = "DevAdminInstancePassRole",
        "Action" = [
          "iam:PassRole"
        ],
        "Resource" = [
          "arn:${local.region_partition}:iam::*:role/INSTANCE*"
        ]
      },
      {
        "Effect" = "Allow",
        "Sid"    = "DevAdminEMRPassRole",
        "Action" = [
          "iam:PassRole"
        ],
        "Resource" = [
          "arn:${local.region_partition}:iam::*:role/EMRSERVICE*"
        ]
      },
      {
        "Effect" = "Deny",
        "Sid"    = "DevAdminKMSECPurchaseDeny",
        "Action" = [
          "elasticache:Purchase*",
          "kms:CancelKeyDeletion",
          "kms:CreateAlias",
          "kms:CreateKey",
          "kms:Delete*",
          "kms:Disable*",
          "kms:Enable*",
          "kms:Put*",
          "kms:Update*",
          "kms:ScheduleKeyDeletion",
          "rds:Purchase*",
          "redshift:Purchase*"
        ],
        "Resource" = "*"
      },
      {
        "Effect" = "Deny",
        "Sid"    = "DevAdminGrantDeny",
        "Action" = [
          "kms:CreateGrant",
          "kms:RevokeGrant"
        ],
        "Resource" = "*"
        # TODO:
        # Condition:
        #   Bool:
        #     'kms:GrantIsForAWSResource': 'false'
      }
    ]
  })
}

resource "aws_iam_policy" "proj_admin_policy" {
  name        = "ProjAdminLimitedPolicy"
  description = "Managed policy for ProjAdminlimitedRole permissions."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect" = "Allow",
        "Sid"    = "ProjAdminGenAccess",
        "Action" = [
          "autoscaling:Describe*",
          "aws-portal:View*",
          "budgets:ViewBudget",
          "config:Describe*",
          "config:Get*",
          "config:List*",
          "cloudformation:*",
          "cloudhsm:Describe*",
          "cloudhsm:Get*",
          "cloudhsm:List*",
          "cloudtrail:Describe*",
          "cloudtrail:Get*",
          "cloudtrail:Lookup*",
          "cloudwatch:*",
          "logs:*",
          "datapipeline:Describe*",
          "datapipeline:List*",
          "directconnect:Describe*",
          "dynamodb:ListTables",
          "dynamodb:DescribeTable",
          "ec2:ActivateLicense",
          "ec2:AllocateAddress",
          "ec2:AssociateAddress",
          "ec2:AttachNetworkInterface",
          "ec2:DeactivateLicense",
          "ec2:DetachNetworkInterface",
          "ec2:DisassociateAddress",
          "ec2:EnableVolumeIO",
          "ec2:ModifyInstanceAttribute",
          "ec2:ModifyNetworkInterfaceAttribute",
          "ec2:ModifySnapshotAttribute",
          "ec2:ModifyVolumeAttribute",
          "ec2:MonitorInstances",
          "ec2:RebootInstances",
          "ec2:ReleaseAddress",
          "ec2:ReportInstanceStatus",
          "ec2:ResetInstanceAttribute",
          "ec2:ResetNetworkInterfaceAttribute",
          "ec2:UnmonitorInstances",
          "ec2:AttachVolume",
          "ec2:CopySnapshot",
          "ec2:CreateSnapshot",
          "ec2:CreateTags",
          "ec2:CreateVolume",
          "ec2:DeleteSnapshot",
          "ec2:DeleteTags",
          "ec2:DeleteVolume",
          "ec2:DetachVolume",
          "ec2:ResetSnapshotAttribute",
          "ec2:ModifySnapshotAttribute",
          "ec2:ModifyVolumeAttribute",
          "ec2:ReportInstanceStatus",
          "ec2:ResetInstanceAttribute",
          "ec2:ResetSnapshotAttribute",
          "ec2:StartInstances",
          "ec2:StopInstances",
          "ec2:DescribeInstanceStatus",
          "ec2:DescribeInstances",
          "ec2:TerminateInstances",
          "ec2:DescribeTags",
          "ec2:Describe*",
          "ec2:GetConsoleOutput",
          "ec2:GetPasswordData",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:CreateSecurityGroup",
          "ec2:DeleteSecurityGroup",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:UpdateSecurityGroupRuleDescriptionsEgress",
          "ec2:UpdateSecurityGroupRuleDescriptionsIngress",
          "elasticache:Describe*",
          "elasticache:List*",
          "elasticloadbalancing:Describe*",
          "elasticmapreduce:Describe*",
          "elasticmapreduce:List*",
          "glacier:Describe*",
          "glacier:Get*",
          "glacier:List*",
          "iam:GenerateCredentialReport",
          "iam:Get*",
          "iam:List*",
          "kinesis:Describe*",
          "kinesis:List*",
          "kms:Describe*",
          "kms:GetKeyPolicy",
          "kms:GetKeyRotationStatus",
          "kms:List*",
          "aws-marketplace:View*",
          "rds:Describe*",
          "rds:List*",
          "redshift:Describe*",
          "redshift:List*",
          "s3:*",
          "sns:*",
          "sqs:Get*",
          "sqs:List*",
          "snowball:Describe*",
          "snowball:Get*",
          "snowball:List*",
          "sts:DecodeAuthorizationMessage",
          "support:*",
          "swf:Count*",
          "swf:Describe*",
          "swf:Get*",
          "swf:List*",
          "trustedadvisor:Exclude*",
          "trustedadvisor:Include*",
          "trustedadvisor:Refresh*",
          "trustedadvisor:Describe*",
          "workspaces:CreateTags",
          "workspaces:DeleteTags",
          "workspaces:Describe*",
          "workspaces:List*",
          "workspaces:ModifyWorkspaceState",
          "workspaces:RebootWorkspaces",
          "workspaces:RebuildWorkspaces",
          "workspaces:StartWorkspaces",
          "workspaces:StopWorkspaces",
          "dms:AddTagsToResource",
          "dms:Describe*",
          "dms:List*",
          "dms:RebootReplicationInstance",
          "dms:RefreshSchemas",
          "dms:ReloadTables",
          "dms:RemoveTagsFromResource",
          "dms:StartReplicationTask",
          "dms:StartReplicationTaskAssessment",
          "dms:StopReplicationTask",
          "dms:TestConnection",
          "ds:CreateSnapshot",
          "ds:DeleteSnapshot",
          "ds:DeregisterEventTopic",
          "ds:Describe*",
          "ds:Get*",
          "ds:List*",
          "ds:RegisterEventTopic",
          "ds:ResetUserPassword",
          "ds:RestoreFromSnapshot",
          "states:Describe*",
          "states:Get*",
          "states:List*",
          "states:Send*",
          "states:StartExecution",
          "states:StopExecution",
          "states:UpdateStateMachine",
          "codedeploy:Get*",
          "codedeploy:List*",
          "codedeploy:PutLifecycleEventHookExecutionStatus",
          "codedeploy:RemoveTagsFromOnPremisesInstances",
          "codedeploy:SkipWaitTimeForInstanceTermination",
          "codedeploy:StartPlatformDeployment",
          "codedeploy:StopDeployment",
          "codedeploy:UpdateApplication",
          "codedeploy:UpdateDeploymentGroup",
          "lambda:Get*",
          "lambda:List*",
          "lambda:PublishLayerVersion",
          "lambda:TagResource",
          "lambda:UntagResource",
          "lambda:UpdateAlias",
          "lambda:UpdateEventSourceMapping",
          "lambda:UpdateFunctionCode",
          "lambda:UpdateFunctionConfiguration",
          "health:Describe*",
          "diode:Describe*",
          "diode:Get*",
          "diode:List*",
          "ec2:*IamInstanceProfile"
        ],
        "Resource" = "*"
      },
      {
        "Effect" = "Allow",
        "Sid"    = "ProjAdminRunInstances",
        "Action" = [
          "ec2:RunInstances"
        ],
        "Resource" = [
          # TODO: whats this?
          # "arn:${local.region_partition}:ec2:*:*:image/ami-fill_in_disabledAMI_IDs*",
          "arn:${local.region_partition}:ec2:*:*:instance/*",
          "arn:${local.region_partition}:ec2:*:*:subnet/*",
          "arn:${local.region_partition}:ec2:*:*:network-interface/*",
          "arn:${local.region_partition}:ec2:*:*:volume/*",
          "arn:${local.region_partition}:ec2:*:*:key-pair/*",
          "arn:${local.region_partition}:ec2:*:*:security-group/*"
        ]
      },
      {
        "Effect" = "Allow",
        "Sid"    = "ProjAdminInstanceAFC2SPassRole",
        "Action" = [
          "iam:PassRole"
        ],
        "Resource" = [
          "arn:${local.region_partition}:iam::*:role/INSTANCE*",
          "arn:${local.region_partition}:iam::*:role/AFC2S*",
        ]
      },
      {
        "Effect" = "Allow",
        "Sid"    = "ProjAdminS3FullAccess",
        "Action" = [
          "s3:*"
        ],
        "Resource" = [
          "arn:${local.region_partition}:s3:::cf-templates*",
          "arn:${local.region_partition}:s3:::cf-templates*/*",
        ]
      },
      {
        "Effect" = "Deny",
        "Sid"    = "ProjAdminManageKMSGrant",
        "Action" = [
          "kms:CreateGrant",
          "kms:RevokeGrant"
        ],
        "Resource" = "*"
        # TODO: 
        # Condition:
        #   Bool:
        #     'kms:GrantIsForAWSResource': 'false'
      },
      {
        "Effect" = "Allow",
        "Sid"    = "ProjAdminKMSDeny",
        "Action" = [
          "kms:CancelKeyDeletion",
          "kms:CreateAlias",
          "kms:CreateKey",
          "kms:Delete*",
          "kms:Disable*",
          "kms:Enable*",
          "kms:Put*",
          "kms:Update*",
          "kms:ScheduleKeyDeletion"
        ],
        "Resource" = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "storage_policy" {
  name        = "StoragePolicy"
  description = "Managed policy for StorageRole permissions."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect" = "Allow",
        "Sid"    = "StorageGenAccess",
        "Action" = [
          "autoscaling:Describe*",
          "aws-portal:View*",
          "budgets:ViewBudget",
          "config:Describe*",
          "config:Get*",
          "config:List*",
          "cloudformation:*",
          "cloudhsm:Describe*",
          "cloudhsm:Get*",
          "cloudhsm:List*",
          "cloudtrail:Describe*",
          "cloudtrail:Get*",
          "cloudtrail:Lookup*",
          "cloudwatch:*",
          "logs:*",
          "datapipeline:Describe*",
          "datapipeline:List*",
          "directconnect:Describe*",
          "dynamodb:ListTables",
          "dynamodb:DescribeTable",
          "ec2:AttachVolume",
          "ec2:CreateVolume",
          "ec2:DeleteVolume",
          "ec2:DetachVolume",
          "ec2:EnableVolumeIO",
          "ec2:ImportVolume",
          "ec2:ModifyVolumeAttribute",
          "ec2:ReportInstanceStatus",
          "ec2:ResetInstanceAttribute",
          "ec2:CopySnapshot",
          "ec2:CreateSnapshot",
          "ec2:CreateTags",
          "ec2:DeleteSnapshot",
          "ec2:DeleteTags",
          "ec2:ModifySnapshotAttribute",
          "ec2:ResetSnapshotAttribute",
          "ec2:DescribeTags",
          "ec2:Describe*",
          "ec2:GetConsoleOutput",
          "elasticache:Describe*",
          "elasticache:List*",
          "elasticloadbalancing:Describe*",
          "elasticmapreduce:Describe*",
          "elasticmapreduce:List*",
          "glacier:*",
          "iam:GenerateCredentialReport",
          "iam:Get*",
          "iam:List*",
          "kinesis:Describe*",
          "kinesis:List*",
          "kms:Describe*",
          "kms:GetKeyPolicy",
          "kms:GetKeyRotationStatus",
          "kms:List*",
          "aws-marketplace:View*",
          "rds:Describe*",
          "rds:List*",
          "redshift:Describe*",
          "redshift:List*",
          "s3:*",
          "sns:Get*",
          "sns:List*",
          "sqs:Get*",
          "sqs:List*",
          "snowball:*",
          "sts:DecodeAuthorizationMessage",
          "support:*",
          "swf:Count*",
          "swf:Describe*",
          "swf:Get*",
          "swf:List*",
          "trustedadvisor:Exclude*",
          "trustedadvisor:Include*",
          "trustedadvisor:Refresh*",
          "trustedadvisor:Describe*",
          "workspaces:Describe*",
          "workspaces:List*",
          "dms:Describe*",
          "dms:List*",
          "ds:Describe*",
          "ds:Get*",
          "ds:List*",
          "states:Describe*",
          "states:Get*",
          "states:List*",
          "codedeploy:Get*",
          "codedeploy:List*",
          "lambda:Get*",
          "lambda:List*",
          "health:Describe*",
          "diode:Describe*",
          "diode:Get*",
          "diode:List*"
        ],
        "Resource" = "*"
      },
      {
        "Effect" = "Deny",
        "Sid"    = "StorageKMSGrantDeny",
        "Action" = [
          "kms:CreateGrant",
          "kms:RevokeGrant"
        ],
        "Resource" = "*"
        # TODO:
        # Condition:
        #   Bool:
        #     'kms:GrantIsForAWSResource': 'false'
      },
      {
        "Effect" = "Deny",
        "Sid"    = "StorageKMSDeny",
        "Action" = [
          "kms:CancelKeyDeletion",
          "kms:CreateAlias",
          "kms:CreateKey",
          "kms:Delete*",
          "kms:Disable*",
          "kms:Enable*",
          "kms:Put*",
          "kms:Update*",
          "kms:ScheduleKeyDeletion"
        ],
        "Resource" = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "database_policy" {
  name        = "DatabasePolicy"
  description = "Managed policy for DatabaseRole permissions."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect" = "Allow",
        "Sid"    = "DatabaseGenAccess",
        "Action" = [
          "autoscaling:Describe*",
          "aws-portal:View*",
          "budgets:ViewBudget",
          "config:Describe*",
          "config:Get*",
          "config:List*",
          "cloudformation:*",
          "cloudhsm:Describe*",
          "cloudhsm:Get*",
          "cloudhsm:List*",
          "cloudtrail:Describe*",
          "cloudtrail:Get*",
          "cloudtrail:Lookup*",
          "cloudwatch:*",
          "logs:*",
          "datapipeline:*",
          "directconnect:Describe*",
          "dynamodb:*",
          "ec2:CopySnapshot",
          "ec2:CreateSnapshot",
          "ec2:CreateTags",
          "ec2:CreateVolume",
          "ec2:DeleteSnapshot",
          "ec2:DeleteTags",
          "ec2:DeleteVolume",
          "ec2:DetachVolume",
          "ec2:ModifySnapshotAttribute",
          "ec2:ModifyVolumeAttribute",
          "ec2:ReportInstanceStatus",
          "ec2:ResetInstanceAttribute",
          "ec2:ResetSnapshotAttribute",
          "ec2:DescribeTags",
          "ec2:Describe*",
          "ec2:GetConsoleOutput",
          "elasticache:*",
          "elasticloadbalancing:Describe*",
          "elasticmapreduce:*",
          "iam:CreateServiceLinkedRole",
          "iam:GenerateCredentialReport",
          "iam:Get*",
          "iam:List*",
          "kinesis:*",
          "kms:Describe*",
          "kms:GetKeyPolicy",
          "kms:GetKeyRotationStatus",
          "kms:List*",
          "aws-marketplace:View*",
          "rds:*",
          "redshift:*",
          "s3:*",
          "sns:*",
          "sqs:*",
          "sts:DecodeAuthorizationMessage",
          "support:*",
          "swf:Count*",
          "swf:Describe*",
          "swf:Get*",
          "swf:List*",
          "trustedadvisor:Exclude*",
          "trustedadvisor:Include*",
          "trustedadvisor:Refresh*",
          "trustedadvisor:Describe*",
          "workspaces:Describe*",
          "workspaces:List*",
          "dms:*",
          "ds:Describe*",
          "ds:Get*",
          "ds:List*",
          "states:Describe*",
          "states:Get*",
          "states:List*",
          "codedeploy:Get*",
          "codedeploy:List*",
          "lambda:Get*",
          "lambda:List*",
          "health:Describe*",
          "diode:Describe*",
          "diode:Get*",
          "diode:List*"
        ],
        "Resource" = "*"
      },
      {
        "Effect" = "Allow",
        "Sid"    = "DatabaseEMRPassRole",
        "Action" = [
          "iam:PassRole"
        ],
        "Resource" = [
          "arn:${local.region_partition}:iam::*:role/EMRSERVICE"
        ]
      },
      {
        "Effect" = "Deny",
        "Sid"    = "DatabaseKMSECPurchaseDeny",
        "Action" = [
          "elasticache:Purchase*",
          "kms:CancelKeyDeletion",
          "kms:CreateAlias",
          "kms:CreateKey",
          "kms:Delete*",
          "kms:Disable*",
          "kms:Enable*",
          "kms:Put*",
          "kms:Update*",
          "kms:ScheduleKeyDeletion",
          "rds:Purchase*",
          "redshift:Purchase*"
        ],
        "Resource" = "*"
      },
      {
        "Effect" = "Deny",
        "Sid"    = "DatabaseKMSGrantDeny",
        "Action" = [
          "kms:CreateGrant",
          "kms:RevokeGrant"
        ],
        "Resource" = "*"
        # TODO:
        # Condition:
        #   Bool:
        #     'kms:GrantIsForAWSResource': 'false'
      }
    ]
  })
}

resource "aws_iam_policy" "s3_only_policy" {
  name        = "S3OnlyPolicy"
  description = "Managed policy for S3OnlyRole permissions."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect" = "Allow",
        "Sid"    = "S3OnlyGenAccess",
        "Action" = [
          "autoscaling:Describe*",
          "aws-portal:View*",
          "budgets:ViewBudget",
          "config:Describe*",
          "config:Get*",
          "config:List*",
          "cloudformation:*",
          "cloudhsm:Describe*",
          "cloudhsm:Get*",
          "cloudhsm:List*",
          "cloudtrail:Describe*",
          "cloudtrail:Get*",
          "cloudtrail:Lookup*",
          "cloudwatch:*",
          "logs:*",
          "datapipeline:Describe*",
          "datapipeline:List*",
          "directconnect:Describe*",
          "dynamodb:ListTables",
          "dynamodb:DescribeTable",
          "ec2:Describe*",
          "ec2:GetConsoleOutput",
          "elasticache:Describe*",
          "elasticache:List*",
          "elasticloadbalancing:Describe*",
          "elasticmapreduce:Describe*",
          "elasticmapreduce:List*",
          "glacier:*",
          "iam:GenerateCredentialReport",
          "iam:Get*",
          "iam:List*",
          "kinesis:Describe*",
          "kinesis:List*",
          "kms:Describe*",
          "kms:GetKeyPolicy",
          "kms:GetKeyRotationStatus",
          "kms:List*",
          "aws-marketplace:View*",
          "rds:Describe*",
          "rds:List*",
          "redshift:Describe*",
          "redshift:List*",
          "s3:*",
          "sns:Get*",
          "sns:List*",
          "sqs:Get*",
          "sqs:List*",
          "snowball:*",
          "sts:DecodeAuthorizationMessage",
          "support:*",
          "swf:Count*",
          "swf:Describe*",
          "swf:Get*",
          "swf:List*",
          "trustedadvisor:Exclude*",
          "trustedadvisor:Include*",
          "trustedadvisor:Refresh*",
          "trustedadvisor:Describe*"
        ],
        "Resource" = "*"
      },
      {
        "Effect" = "Deny",
        "Sid"    = "S3OnlyKMSGrantDeny",
        "Action" = [
          "kms:CreateGrant",
          "kms:RevokeGrant"
        ],
        "Resource" = "*"
        # TODO:
        # Condition:
        #   Bool:
        #     'kms:GrantIsForAWSResource': 'false'
      },
      {
        "Effect" = "Deny",
        "Sid"    = "S3OnlyKMSDeny",
        "Action" = [
          "kms:CancelKeyDeletion",
          "kms:CreateAlias",
          "kms:CreateKey",
          "kms:Delete*",
          "kms:Disable*",
          "kms:Enable*",
          "kms:Put*",
          "kms:Update*",
          "kms:ScheduleKeyDeletion"
        ],
        "Resource" = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "emr_service_policy" {
  name        = "EMRServicePolicy"
  description = "Managed policy for EMRServiceRole permissions."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect" = "Allow",
        "Sid"    = "EMRServiceGenAccess",
        "Action" = [
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:CreateSecurityGroup",
          "ec2:DeleteSecurityGroup",
          "ec2:DescribeSecurityGroups",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:DescribeDhcpOptions",
          "ec2:DescribeNetworkAcls",
          "ec2:DescribeRouteTables",
          "ec2:DescribeSubnets",
          "ec2:DescribeVpcAttribute",
          "ec2:DescribeVpcEndpoints",
          "ec2:DescribeVpcEndpointServices",
          "ec2:DescribeVpcs",
          "ec2:CancelSpotInstanceRequests",
          "ec2:CreateTags",
          "ec2:CreateNetworkInterface",
          "ec2:DeleteNetworkInterface",
          "ec2:DeleteTags",
          "ec2:DeleteVolume",
          "ec2:DescribeAvailabilityZones",
          "ec2:DescribeAccountAttributes",
          "ec2:DescribeInstances",
          "ec2:DescribeInstanceStatus",
          "ec2:DescribeKeyPairs",
          "ec2:DescribeNetworkInterfaces",
          "ec2:DescribePrefixLists",
          "ec2:DescribeSpotInstanceRequests",
          "ec2:DescribeSpotPriceHistory",
          "ec2:DescribeVolumeStatus",
          "ec2:DescribeVolumes",
          "ec2:DetachNetworkInterface",
          "ec2:DetachVolume",
          "ec2:ModifyImageAttribute",
          "ec2:ModifyInstanceAttribute",
          "ec2:RequestSpotInstances",
          "ec2:RunInstances",
          "ec2:TerminateInstances",
          "iam:GetRole",
          "iam:GetRolePolicy",
          "iam:ListInstanceProfiles",
          "iam:ListRolePolicies",
          "s3:CreateBucket",
          "s3:Get*",
          "s3:List*",
          "sqs:*"
        ],
        "Resource" = "*"
      },
      {
        "Effect" = "Allow",
        "Sid"    = "EMRServiceInstancePassRole",
        "Action" = [
          "iam:PassRole"
        ],
        "Resource" = [
          "arn:${local.region_partition}:iam::*:role/INSTANCEEMR"
        ]
      },
      {
        "Effect" = "Deny",
        "Sid"    = "EMRServiceKMSGrantDeny",
        "Action" = [
          "kms:CreateGrant",
          "kms:RevokeGrant"
        ],
        "Resource" = "*"
        # TODO
        # Condition:
        #   Bool:
        #     'kms:GrantIsForAWSResource': 'false'
      },
      {
        "Effect" = "Deny",
        "Sid"    = "EMRServiceKMSDeny",
        "Action" = [
          "kms:CancelKeyDeletion",
          "kms:CreateAlias",
          "kms:CreateKey",
          "kms:Delete*",
          "kms:Disable*",
          "kms:Enable*",
          "kms:Put*",
          "kms:Update*",
          "kms:ScheduleKeyDeletion",
        ],
        "Resource" = "*"
      }


    ]
  })
}

resource "aws_iam_policy" "instance_emr_policy" {
  name        = "InstanceEMRPolicy"
  description = "Managed policy for InstanceEMRRole permissions."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect" = "Allow",
        "Sid"    = "InstanceEMRGenAccess",
        "Action" = [
          "cloudwatch:*",
          "dynamodb:*",
          "ec2:Describe*",
          "ec2:GetConsoleOutput",
          "elasticmapreduce:Describe*",
          "elasticmapreduce:List*",
          "kinesis:*",
          "rds:Describe*",
          "rds:List*",
          "s3:*",
          "sns:*",
          "sqs:*",
        ],
        "Resource" = "*"
      },
      {
        "Effect" = "Deny",
        "Sid"    = "InstanceEMRKMSGrantDeny",
        "Action" = [
          "kms:CreateGrant",
          "kms:RevokeGrant"
        ],
        "Resource" = "*"
        # TODO
        #  Condition:
        #     Bool:
        #       'kms:GrantIsForAWSResource': 'false'        
      },
      {
        "Effect" = "Deny",
        "Sid"    = "InstanceEMRKMSDeny",
        "Action" = [
          "kms:CancelKeyDeletion",
          "kms:CreateAlias",
          "kms:CreateKey",
          "kms:Delete*",
          "kms:Disable*",
          "kms:Enable*",
          "kms:Put*",
          "kms:Update*",
          "kms:ScheduleKeyDeletion"
        ],
        "Resource" = "*"
      },
    ]
  })
}

resource "aws_iam_policy" "instance_policy" {
  name        = "InstancePolicy"
  description = "Managed policy for InstanceRole permissions."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect" = "Allow",
        "Sid"    = "InstanceGenAccess",
        "Action" = [
          "cloudformation:*",
          "cloudwatch:*",
          "logs:*",
          "ec2:CopySnapshot",
          "ec2:CreateSnapshot",
          "ec2:CreateTags",
          "ec2:CreateVolume",
          "ec2:DeleteSnapshot",
          "ec2:DeleteTags",
          "ec2:DeleteVolume",
          "ec2:DetachVolume",
          "ec2:ModifySnapshotAttribute",
          "ec2:ModifyVolumeAttribute",
          "ec2:ReportInstanceStatus",
          "ec2:ResetInstanceAttribute",
          "ec2:ResetSnapshotAttribute",
          "ec2:DescribeInstanceAttribute",
          "ec2:DescribeInstanceStatus",
          "ec2:DescribeInstances",
          "ec2:DescribeRegions",
          "ec2:DescribeSnapshotAttribute",
          "ec2:DescribeSnapshots",
          "ec2:DescribeTags",
          "ec2:DescribeVolumeAttribute",
          "ec2:DescribeVolumeStatus",
          "ec2:DescribeVolumes",
          "s3:GetBucketLocation",
          "s3:ListAllMyBuckets"
        ],
        "Resource" = "*"
      },
      {
        "Effect" = "Allow",
        "Sid"    = "InstanceS3FullAccess",
        "Action" = [
          "s3:*"
        ],
        "Resource" = [
          "arn:${local.region_partition}:s3:::cf-templates*",
          "arn:${local.region_partition}:s3:::cf-templates*/*"
        ]
      },
      {
        "Effect" = "Deny",
        "Sid"    = "InstanceKMSGrantDeny",
        "Action" = [
          "kms:CreateGrant",
          "kms:RevokeGrant"
        ],
        "Resource" = "*"
        # TODO
        #       Condition:
        # Bool:
        #   'kms:GrantIsForAWSResource': 'false'
      },
      {
        "Effect" = "Deny",
        "Sid"    = "InstanceKMSDeny",
        "Action" = [
          "kms:CancelKeyDeletion",
          "kms:CreateAlias",
          "kms:CreateKey",
          "kms:Delete*",
          "kms:Disable*",
          "kms:Enable*",
          "kms:Put*",
          "kms:Update*",
          "kms:ScheduleKeyDeletion"
        ],
        "Resource" = "*"
      },
    ]
  })
}

resource "aws_iam_policy" "config_manager_policy" {
  name        = "ConfigManagerPolicy"
  description = "Managed policy for ConfigManagerRole permissions."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect" = "Allow",
        "Sid"    = "ConfigManagerGenAccess",
        "Action" = [
          "autoscaling:Describe*",
          "aws-portal:View*",
          "budgets:ViewBudget",
          "config:*",
          "cloudformation:Describe*",
          "cloudformation:EstimateTemplateCost",
          "cloudformation:Get*",
          "cloudformation:List*",
          "cloudformation:PreviewStackUpdate",
          "cloudformation:ValidateTemplate",
          "cloudhsm:Describe*",
          "cloudhsm:Get*",
          "cloudhsm:List*",
          "cloudtrail:Describe*",
          "cloudtrail:Get*",
          "cloudtrail:Lookup*",
          "cloudwatch:Describe*",
          "cloudwatch:Get*",
          "cloudwatch:List*",
          "logs:Describe*",
          "logs:Get*",
          "logs:Test*",
          "datapipeline:Describe*",
          "datapipeline:List*",
          "directconnect:Describe*",
          "dynamodb:ListTables",
          "dynamodb:DescribeTable",
          "ec2:Describe*",
          "ec2:GetConsoleOutput",
          "elasticache:Describe*",
          "elasticache:List*",
          "elasticloadbalancing:Describe*",
          "elasticmapreduce:Describe*",
          "elasticmapreduce:List*",
          "glacier:Describe*",
          "glacier:Get*",
          "glacier:List*",
          "iam:PassRole",
          "iam:GenerateCredentialReport",
          "iam:Get*",
          "iam:List*",
          "kinesis:Describe*",
          "kinesis:List*",
          "kms:Describe*",
          "kms:GetKeyPolicy",
          "kms:GetKeyRotationStatus",
          "kms:List*",
          "aws-marketplace:View*",
          "rds:Describe*",
          "rds:List*",
          "redshift:Describe*",
          "redshift:List*",
          "s3:GetBucket*",
          "s3:GetLifecycle*",
          "s3:GetObjectAcl",
          "s3:GetObjectVersionAcl",
          "s3:List*",
          "sns:Get*",
          "sns:List*",
          "sqs:Get*",
          "sqs:List*",
          "snowball:Describe*",
          "snowball:Get*",
          "snowball:List*",
          "swf:Count*",
          "swf:Describe*",
          "swf:Get*",
          "swf:List*"
        ],
        "Resource" = "*"
      },
      {
        "Effect" = "Allow",
        "Sid"    = "ConfigManagerS3FullAccess",
        "Action" = [
          "s3:*"
        ],
        "Resource" = [
          "arn:${local.region_partition}:s3:::configdata*",
          "arn:${local.region_partition}:s3:::configdata*/*"
        ]
      },
      {
        "Effect" = "Allow",
        "Sid"    = "ConfigManagerS3ReadAccess",
        "Action" = [
          "s3:Get*",
          "s3:List*"
        ],
        "Resource" = [
          "arn:${local.region_partition}:s3:::*billing*",
          "arn:${local.region_partition}:s3:::*billing*/*"
        ]
      },
      {
        "Effect" = "Allow",
        "Sid"    = "ConfigManagerTrustedAdvisorCost",
        "Action" = [
          "trustedadvisor:Exclude*",
          "trustedadvisor:Include*",
          "trustedadvisor:Refresh*",
          "trustedadvisor:Describe*"
        ],
        "Resource" = [
          "arn:${local.region_partition}:trustedadvisor:*:*:checks/cost_optimizing/*"
        ]
      },
      {
        "Effect" = "Allow",
        "Sid"    = "ConfigManagerTrustedAdvisorPerformance",
        "Action" = [
          "trustedadvisor:Exclude*",
          "trustedadvisor:Include*",
          "trustedadvisor:Refresh*",
          "trustedadvisor:Describe*"
        ],
        "Resource" = [
          "arn:${local.region_partition}:trustedadvisor:*:*:checks/performance/*"
        ]
      },
      {
        "Effect" = "Allow",
        "Sid"    = "ConfigManagerTrustedAdvisorFaultTolerance",
        "Action" = [
          "trustedadvisor:Exclude*",
          "trustedadvisor:Include*",
          "trustedadvisor:Refresh*",
          "trustedadvisor:Describe*"
        ],
        "Resource" = [
          "arn:${local.region_partition}:trustedadvisor:*:*:checks/fault_tolerance/*"
        ]
      },
      {
        "Effect" = "Deny",
        "Sid"    = "ConfigManagerKMSDeny",
        "Action" = [
          "kms:CreateGrant",
          "kms:RevokeGrant",
          "kms:CancelKeyDeletion",
          "kms:CreateAlias",
          "kms:CreateKey",
          "kms:Delete*",
          "kms:Disable*",
          "kms:Enable*",
          "kms:Put*",
          "kms:Update*",
          "kms:ScheduleKeyDeletion",
          "kms:Decrypt*",
          "kms:Encrypt*",
          "kms:Generate*",
          "kms:ReEncrypt*"
        ],
        "Resource" = "*"
      },
      {
        "Effect" = "Deny",
        "Sid"    = "ConfigManagerKMSGrantDeny",
        "Action" = [
          "kms:CreateGrant",
          "kms:RevokeGrant"
        ],
        "Resource" = "*"
        # TODO
        # Condition:
        #   Bool:
        #     'kms:GrantIsForAWSResource': 'false'
      }
    ]
  })
}

resource "aws_iam_policy" "config_policy" {
  name        = "ConfigPolicy"
  description = "Managed policy for ConfigRole permissions."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect" = "Allow",
        "Sid"    = "ConfigGenAccess",
        "Action" = [
          "autoscaling:Describe*",
          "aws-portal:View*",
          "budgets:ViewBudget",
          "config:Describe*",
          "config:Get*",
          "config:List*",
          "cloudformation:Describe*",
          "cloudformation:EstimateTemplateCost",
          "cloudformation:Get*",
          "cloudformation:List*",
          "cloudformation:PreviewStackUpdate",
          "cloudformation:ValidateTemplate",
          "cloudhsm:Describe*",
          "cloudhsm:Get*",
          "cloudhsm:List*",
          "cloudtrail:Describe*",
          "cloudtrail:Get*",
          "cloudtrail:Lookup*",
          "cloudwatch:Describe*",
          "cloudwatch:Get*",
          "cloudwatch:List*",
          "logs:Describe*",
          "logs:Get*",
          "logs:Test*",
          "datapipeline:Describe*",
          "datapipeline:List*",
          "directconnect:Describe*",
          "dynamodb:ListTables",
          "dynamodb:DescribeTable",
          "ec2:Describe*",
          "ec2:GetConsoleOutput",
          "elasticache:Describe*",
          "elasticache:List*",
          "elasticloadbalancing:Describe*",
          "elasticmapreduce:Describe*",
          "elasticmapreduce:List*",
          "glacier:Describe*",
          "glacier:Get*",
          "glacier:List*",
          "iam:GenerateCredentialReport",
          "iam:Get*",
          "iam:List*",
          "kinesis:Describe*",
          "kinesis:List*",
          "kms:Describe*",
          "kms:GetKeyPolicy",
          "kms:GetKeyRotationStatus",
          "kms:List*",
          "rds:Describe*",
          "rds:List*",
          "redshift:Describe*",
          "redshift:List*",
          "s3:GetAccelerateConfiguration",
          "s3:GetBucketAcl",
          "s3:GetBucketCORS",
          "s3:GetBucketLocation",
          "s3:GetBucketLogging",
          "s3:GetBucketNotification",
          "s3:GetBucketPolicy",
          "s3:GetBucketRequestPayment",
          "s3:GetBucketTagging",
          "s3:GetBucketVersioning",
          "s3:GetBucketWebsite",
          "s3:GetLifecycleConfiguration",
          "s3:GetReplicationConfiguration",
          "s3:ListAllMyBuckets",
          "sns:Get*",
          "sns:List*",
          "sqs:Get*",
          "sqs:List*",
          "swf:Count*",
          "swf:Describe*",
          "swf:Get*",
          "swf:List*",
        ]
        "Resource" = "*"
      },
      {
        "Effect" = "Allow",
        "Sid"    = "ConfigS3PutAccess",
        "Action" = [
          "s3:PutObject"
        ]
        "Resource" = [
          "arn:${local.region_partition}:s3:::configdata*",
          "arn:${local.region_partition}:s3:::configdata*/*"
        ]
      },
      {
        "Effect" = "Allow",
        "Sid"    = "ConfigS3ReadAccess",
        "Action" = [
          "s3:Get*",
          "s3:List*"
        ]
        "Resource" = [
          "arn:${local.region_partition}:s3:::*billing*",
          "arn:${local.region_partition}:s3:::*billing*/*"
        ]
      },
      {
        "Effect" = "Deny",
        "Sid"    = "ConfigKMSDeny",
        "Action" = [
          "kms:CreateGrant",
          "kms:RevokeGrant",
          "kms:CancelKeyDeletion",
          "kms:CreateAlias",
          "kms:CreateKey",
          "kms:Delete*",
          "kms:Disable*",
          "kms:Enable*",
          "kms:Put*",
          "kms:Update*",
          "kms:ScheduleKeyDeletion",
          "kms:Decrypt*",
          "kms:Encrypt*",
          "kms:Generate*",
          "kms:ReEncrypt*"
        ]
        "Resource" = "*"
      },
      {
        "Effect" = "Deny",
        "Sid"    = "ConfigKMSGrantDeny",
        "Action" = [
          "kms:CreateGrant",
          "kms:RevokeGrant"
        ]
        "Resource" = "*"
        # TODO
        #       Condition:
        # Bool:
        #   'kms:GrantIsForAWSResource': 'false'
      }
    ]
  })
}

resource "aws_iam_policy" "pipeline_service_policy" {
  name        = "PipelineServicePolicy"
  description = "Managed policy for PipelineServiceRole permissions."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect" = "Allow",
        "Sid"    = "PipelineGenAccess",
        "Action" = [
          "cloudwatch:*",
          "logs:*",
          "datapipeline:DescribeObjects",
          "datapipeline:EvaluateExpression",
          "dynamodb:BatchGetItem",
          "dynamodb:DescribeTable",
          "dynamodb:GetItem",
          "dynamodb:Query",
          "dynamodb:Scan",
          "dynamodb:UpdateTable",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:CreateSecurityGroup",
          "ec2:CreateTags",
          "ec2:DeleteTags",
          "ec2:Describe*",
          "ec2:ModifyImageAttribute",
          "ec2:ModifyInstanceAttribute",
          "ec2:RunInstances",
          "ec2:StartInstances",
          "ec2:StopInstances",
          "ec2:TerminateInstances",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:DeleteSecurityGroup",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:DescribeNetworkInterfaces",
          "ec2:CreateNetworkInterface",
          "ec2:DeleteNetworkInterface",
          "ec2:DetachNetworkInterface",
          "elasticmapreduce:*",
          "iam:GetInstanceProfile",
          "iam:GetRole",
          "iam:GetRolePolicy",
          "iam:ListAttachedRolePolicies",
          "iam:ListRolePolicies",
          "iam:ListInstanceProfiles",
          "rds:DescribeDBInstances",
          "rds:DescribeDBSecurityGroups",
          "redshift:DescribeClusters",
          "redshift:DescribeClusterSecurityGroups",
          "s3:CreateBucket",
          "s3:DeleteObject",
          "s3:Get*",
          "s3:List*",
          "s3:Put*",
          "sns:GetTopicAttributes",
          "sns:ListTopics",
          "sns:Publish",
          "sns:Subscribe",
          "sns:Unsubscribe",
          "sqs:CreateQueue",
          "sqs:Delete*",
          "sqs:GetQueue*",
          "sqs:PurgeQueue",
          "sqs:ReceiveMessage",
          "sqs:Get*",
          "sqs:List*"
        ],
        "Resource" = "*"
      },
      {
        "Effect" = "Allow",
        "Sid"    = "PipelineGenPassRole",
        "Action" = [
          "iam:PassRole"
        ],
        "Resource" = [
          "arn:${local.region_partition}:iam::*:role/EMRSERVICE"
        ]
      },
      {
        "Effect" = "Deny",
        "Sid"    = "PipelineKMSDeny",
        "Action" = [
          "kms:CreateGrant",
          "kms:RevokeGrant",
          "kms:CancelKeyDeletion",
          "kms:CreateAlias",
          "kms:CreateKey",
          "kms:Delete*",
          "kms:Disable*",
          "kms:Enable*",
          "kms:Put*",
          "kms:Update*",
          "kms:ScheduleKeyDeletion",
          "kms:Decrypt*",
          "kms:Encrypt*",
          "kms:Generate*",
          "kms:ReEncrypt*"
        ],
        "Resource" = "*"
      },
      {
        "Effect" = "Deny",
        "Sid"    = "PipelineKMSGrantDeny",
        "Action" = [
          "kms:CreateGrant",
          "kms:RevokeGrant"
        ],
        "Resource" = "*"
        # TODO
        #       Condition:
        # Bool:
        #   'kms:GrantIsForAWSResource': 'false'
      },
    ]
  })
}

resource "aws_iam_policy" "instance_pipeline_policy" {
  name        = "InstancePipelinePolicy"
  description = "Managed policy for InstancePipelineRole permissions."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect" = "Allow",
        "Sid"    = "InstancePipelineGenAccess",
        "Action" = [
          "cloudwatch:*",
          "logs:*",
          "datapipeline:*",
          "dynamodb:*",
          "ec2:Describe*",
          "ec2:GetConsoleOutput",
          "elasticmapreduce:Describe*",
          "elasticmapreduce:AddJobFlowSteps",
          "elasticmapreduce:ListInstance*",
          "elasticmapreduce:ModifyInstanceGroups",
          "rds:Describe*",
          "rds:List*",
          "redshift:Describe*",
          "redshift:List*",
          "s3:*",
          "sns:*",
          "sqs:*"
        ],
        "Resource" = "*"
      },
      {
        "Effect" = "Deny",
        "Sid"    = "InstancePipelineKMSDeny",
        "Action" = [
          "kms:CreateGrant",
          "kms:RevokeGrant",
          "kms:CancelKeyDeletion",
          "kms:CreateAlias",
          "kms:CreateKey",
          "kms:Delete*",
          "kms:Disable*",
          "kms:Enable*",
          "kms:Put*",
          "kms:Update*",
          "kms:ScheduleKeyDeletion",
          "kms:Decrypt*",
          "kms:Encrypt*",
          "kms:Generate*",
          "kms:ReEncrypt*"
        ],
        "Resource" = "*"
      },
      {
        "Effect" = "Deny",
        "Sid"    = "InstancePipelineKMSGrantDeny",
        "Action" = [
          "kms:CreateGrant",
          "kms:RevokeGrant"
        ],
        "Resource" = "*"
        # TODO
        #       Condition:
        # Bool:
        #   'kms:GrantIsForAWSResource': 'false'
      },
    ]
  })
}

resource "aws_iam_policy" "ent_eng_policy" {
  name        = "EntEngPolicy"
  description = "Managed policy for EntEngRole permissions."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect" = "Allow",
        "Sid"    = "EntEngGenAccess",
        "Action" = [
          "autoscaling:*",
          "aws-portal:*",
          "budgets:ViewBudget",
          "config:*",
          "cloudformation:*",
          "cloudhsm:*",
          "cloudtrail:Describe*",
          "cloudtrail:Get*",
          "cloudtrail:Lookup*",
          "cloudwatch:*",
          "logs:*",
          "datapipeline:*",
          "directconnect:*",
          "dynamodb:*",
          "ec2:AcceptVpcPeeringConnection",
          "ec2:ActivateLicense",
          "ec2:AllocateAddress",
          "ec2:AssignPrivateIpAddresses",
          "ec2:AssociateAddress",
          "ec2:AssociateDhcpOptions",
          "ec2:AssociateIamInstanceProfile",
          "ec2:AssociateRouteTable",
          "ec2:AttachInternetGateway",
          "ec2:AttachNetworkInterface",
          "ec2:AttachVolume",
          "ec2:AttachVpnGateway",
          "ec2:AuthorizeSecurityGroupEgress",
          "ec2:AuthorizeSecurityGroupIngress",
          "ec2:BundleInstance",
          "ec2:CancelBundleTask",
          "ec2:CancelConversionTask",
          "ec2:CancelExportTask",
          "ec2:CancelSpotInstanceRequests",
          "ec2:ConfirmProductInstance",
          "ec2:CopyImage",
          "ec2:CopySnapshot",
          "ec2:CreateCustomerGateway",
          "ec2:CreateDhcpOptions",
          "ec2:CreateFlowLogs",
          "ec2:CreateImage",
          "ec2:CreateInstanceExportTask",
          "ec2:CreateInternetGateway",
          "ec2:CreateKeyPair",
          "ec2:CreateNetworkAcl",
          "ec2:CreateNetworkAclEntry",
          "ec2:CreateNetworkInterface",
          "ec2:CreatePlacementGroup",
          "ec2:CreateRoute",
          "ec2:CreateRouteTable",
          "ec2:CreateSecurityGroup",
          "ec2:CreateSnapshot",
          "ec2:CreateSpotDatafeedSubscription",
          "ec2:CreateSubnet",
          "ec2:CreateTags",
          "ec2:CreateVolume",
          "ec2:CreateVpc",
          "ec2:CreateVpcEndpoint",
          "ec2:CreateVpcPeeringConnection",
          "ec2:CreateVpnConnection",
          "ec2:CreateVpnConnectionRoute",
          "ec2:CreateVpnGateway",
          "ec2:DeactivateLicense",
          "ec2:DeleteCustomerGateway",
          "ec2:DeleteDhcpOptions",
          "ec2:DeleteInternetGateway",
          "ec2:DeleteFlowLogs",
          "ec2:DeleteKeyPair",
          "ec2:DeleteNetworkAcl",
          "ec2:DeleteNetworkAclEntry",
          "ec2:DeleteNetworkInterface",
          "ec2:DeletePlacementGroup",
          "ec2:DeleteRoute",
          "ec2:DeleteRouteTable",
          "ec2:DeleteSecurityGroup",
          "ec2:DeleteSnapshot",
          "ec2:DeleteSpotDatafeedSubscription",
          "ec2:DeleteSubnet",
          "ec2:DeleteTags",
          "ec2:DeleteVolume",
          "ec2:DeleteVpc",
          "ec2:DeleteVpcEndpoints",
          "ec2:DeleteVpcPeeringConnection",
          "ec2:DeleteVpnConnection",
          "ec2:DeleteVpnConnectionRoute",
          "ec2:DeleteVpnGateway",
          "ec2:DeregisterImage",
          "ec2:Describe*",
          "ec2:DetachInternetGateway",
          "ec2:DetachNetworkInterface",
          "ec2:DetachVolume",
          "ec2:DetachVpnGateway",
          "ec2:DisableVgwRoutePropagation",
          "ec2:DisassociateAddress",
          "ec2:DisassociateIamInstanceProfile",
          "ec2:DisassociateRouteTable",
          "ec2:EnableVgwRoutePropagation",
          "ec2:EnableVolumeIO",
          "ec2:GetConsoleOutput",
          "ec2:GetPasswordData",
          "ec2:ImportInstance",
          "ec2:ImportKeyPair",
          "ec2:ImportVolume",
          "ec2:ModifyImageAttribute",
          "ec2:ModifyInstanceAttribute",
          "ec2:ModifyNetworkInterfaceAttribute",
          "ec2:ModifySnapshotAttribute",
          "ec2:ModifyVolume*",
          "ec2:ModifyVpcAttribute",
          "ec2:ModifyVpcEndpoint",
          "ec2:MonitorInstances",
          "ec2:RebootInstances",
          "ec2:RegisterImage",
          "ec2:RejectVpcPeeringConnection",
          "ec2:ReleaseAddress",
          "ec2:ReplaceIamInstanceProfileAssociation",
          "ec2:ReplaceNetworkAclAssociation",
          "ec2:ReplaceNetworkAclEntry",
          "ec2:ReplaceRoute",
          "ec2:ReplaceRouteTableAssociation",
          "ec2:ReportInstanceStatus",
          "ec2:RequestSpotInstances",
          "ec2:ResetImageAttribute",
          "ec2:ResetInstanceAttribute",
          "ec2:ResetNetworkInterfaceAttribute",
          "ec2:ResetSnapshotAttribute",
          "ec2:RevokeSecurityGroupEgress",
          "ec2:RevokeSecurityGroupIngress",
          "ec2:RunInstances",
          "ec2:StartInstances",
          "ec2:StopInstances",
          "ec2:TerminateInstances",
          "ec2:UnassignPrivateIpAddresses",
          "ec2:UnmonitorInstances",
          "ec2:CreateNatGateway",
          "ec2:DeleteNatGateway",
          "elasticache:*",
          "elasticloadbalancing:*",
          "elasticmapreduce:*",
          "glacier:*",
          "iam:*",
          "kinesis:*",
          "kms:Describe*",
          "kms:GetKeyPolicy",
          "kms:GetKeyRotationStatus",
          "kms:List*",
          "aws-marketplace:*",
          "rds:*",
          "redshift:*",
          "s3:*",
          "sns:*",
          "sqs:*",
          "snowball:Describe*",
          "snowball:Get*",
          "snowball:List*",
          "ssm:*",
          "sts:DecodeAuthorizationMessage",
          "sts:AssumeRole",
          "support:*",
          "swf:*",
          "trustedadvisor:*",
          "workspaces:*",
          "dms:*",
          "ds:*",
          "states:*",
          "codedeploy:*",
          "lambda:*",
          "health:Describe*",
          "diode:*",
          "events:*",
          "ecs:*",
          "ecr:*",
          "sagemaker:*",
          "ec2:*ReservedInstances*",
          "events:*",
          "apigateway:*",
          "route53:*"
        ],
        "Resource" = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "sec_eng_policy" {
  name        = "SecEngPolicy"
  description = "Managed policy for SecEngRole permissions."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect" = "Allow",
        "Sid"    = "SecEngGenAccess",
        "Action" = [
          "cloudformation:*",
          "ec2:AssociateRouteTable",
          "ec2:AttachInternetGateway",
          "ec2:CreateInternetGateway",
          "ec2:CreateRoute",
          "ec2:CreateRouteTable",
          "ec2:DeleteInternetGateway",
          "ec2:DeleteRoute",
          "ec2:DeleteRouteTable",
          "ec2:Describe*",
          "ec2:DetachInternetGateway",
          "ec2:DisassociateRouteTable",
          "ec2:Get*",
          "ec2:List*",
          "ec2:ReplaceRoute",
          "ec2:ReplaceRouteTableAssociation",
          "ec2:*Tags",
          "iam:*",
          "s3:CreateBucket",
          "s3:DeleteBucket",
          "s3:DeleteObject",
          "s3:Get*",
          "s3:List*",
          "s3:Put*",
          "autoscaling:Describe*"
        ],
        "Resource" = "*"
      },
      {
        "Effect" = "Deny",
        "Sid"    = "SecEngKMSDeny",
        "Action" = [
          "kms:CreateGrant",
          "kms:RevokeGrant",
          "kms:CancelKeyDeletion",
          "kms:CreateAlias",
          "kms:CreateKey",
          "kms:Delete*",
          "kms:Disable*",
          "kms:Enable*",
          "kms:Put*",
          "kms:Update*",
          "kms:ScheduleKeyDeletion",
          "kms:Decrypt*",
          "kms:Encrypt*",
          "kms:Generate*",
          "kms:ReEncrypt*"
        ],
        "Resource" = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "role_creator_policy" {
  name        = "RoleCreatorPolicy"
  description = "Managed policy to delegate role creation and enforce permissions boundary."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect" = "Allow",
        "Sid"    = "RoleCreatorCustomPolicies",
        "Action" = [
          "iam:CreatePolicy*",
          "iam:DeletePolicy*",
          "iam:SetDefaultPolicyVersion",
          "iam:CreatePolicyVersion",
          "iam:DeletePolicyVersion",
        ],
        "Resource" = [
          "arn:${local.region_partition}:iam::${local.caller_account_id}:policy/AFC2S*"
        ]
      },
      {
        "Effect" = "Allow",
        "Sid"    = "RoleCreatorCreateCustomRolesEnforceBoundary",
        "Action" = [
          "iam:AttachRolePolicy",
          "iam:CreateRole",
          "iam:DetachRolePolicy",
          "iam:PutRolePermissionsBoundary",
          "iam:PutRolePolicy"
        ],
        "Resource" = "arn:${local.region_partition}:iam::${local.caller_account_id}:role/AFC2S*"
        # TODO
        # Condition:
        #   StringLike:
        #     'iam:PermissionsBoundary': !Sub 'arn:${RegionPartition}:iam::${AWS::AccountId}:policy/ProjAdminPolicy'
      },
      {
        "Effect" = "Allow",
        "Sid"    = "RoleCreatorEditCustomRoles",
        "Action" = [
          "iam:DeleteRole",
          "iam:UpdateRole",
          "iam:TagRole",
          "iam:UpdateAssumeRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:UntagRole"
        ],
        "Resource" = "arn:${local.region_partition}:iam::${local.caller_account_id}:role/AFC2S*"
      },
      {
        "Effect" = "Allow",
        "Sid"    = "RoleCreatorCustomInstanceProfiles",
        "Action" = [
          "iam:AddRoleToInstanceProfile",
          "iam:CreateInstanceProfile",
          "iam:DeleteInstanceProfile",
          "iam:RemoveRoleFromInstanceProfile"
        ],
        "Resource" = "arn:${local.region_partition}:iam::${local.caller_account_id}:instance-profile/AFC2S*"
      }
    ]
  })
}

resource "aws_iam_policy" "ent_business_policy" {
  name        = "EntBusinessPolicy"
  description = "Managed policy for AFC2SBusinessRole permissions."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect" = "Allow",
        "Sid"    = "Afc2sBusinessGenAccess",
        "Action" = [
          "aws-portal:ModifyAccount",
          "aws-portal:ModifyBilling",
          "aws-portal:ModifyPaymentMethods",
          "aws-portal:View*",
          "budgets:ModifyBudget",
          "budgets:ViewBudget",
          "cloudwatch:*",
          "ce:*",
          "ec2:DescribeAccountAttributes",
          "ec2:DescribeAvailabilityZones",
          "ec2:*ReservedInstances*",
          "elasticache:Purchase*",
          "elasticache:DescribeReserved*",
          "aws-marketplace:View*",
          "rds:Purchase*",
          "rds:DescribeReserved*",
          "redshift:Purchase*",
          "redshift:DescribeReserved*",
          "s3:ListAllMyBuckets",
          "sns:Get*",
          "sns:List*",
          "support:*",
          "pricing:DescribeServices",
          "pricing:GetAttributeValues",
          "pricing:GetProducts",
          "purchase-orders:ViewPurchaseOrders",
          "purchase-orders:ModifyPurchaseOrders",
          "cur:PutReportDefinition",
          "cur:ModifyReportDefinition",
          "cur:DescribeReportDefinitions",
          "organizations:*"
        ],
        "Resource" = "*"
      },
      {
        "Effect" = "Allow",
        "Sid"    = "Afc2sBusinessS3ReadOnly",
        "Action" = [
          "s3:Get*",
          "s3:List*"
        ],
        "Resource" = [
          "arn:${local.region_partition}:s3:::*billing*",
          "arn:${local.region_partition}:s3:::*billing*/*",
          "arn:${local.region_partition}:s3:::diode-delivery-bucket-*"
        ]
      },
      {
        "Effect" = "Allow",
        "Sid"    = "Afc2sBusinessSNSFullAccess",
        "Action" = [
          "sns:*"
        ],
        "Resource" = "arn:${local.region_partition}:sns:*:*:aws_budget*"
      },
      {
        "Effect" = "Allow",
        "Sid"    = "Afc2sBusinessTrustedAdvisorCost",
        "Action" = [
          "trustedadvisor:Exclude*",
          "trustedadvisor:Include*",
          "trustedadvisor:Refresh*",
          "trustedadvisor:Describe*"
        ],
        "Resource" = "arn:${local.region_partition}:trustedadvisor:*:*:checks/cost_optimizing/*"
      },
      {
        "Effect" = "Deny",
        "Sid"    = "Afc2sBusinessKMSDeny",
        "Action" = [
          "kms:CreateGrant",
          "kms:RevokeGrant",
          "kms:CancelKeyDeletion",
          "kms:CreateAlias",
          "kms:CreateKey",
          "kms:Delete*",
          "kms:Disable*",
          "kms:Enable*",
          "kms:Put*",
          "kms:Update*",
          "kms:ScheduleKeyDeletion",
          "kms:Decrypt*",
          "kms:Encrypt*",
          "kms:Generate*",
          "kms:ReEncrypt*"
        ],
        "Resource" = "*"
      }
    ]
  })
}

resource "aws_iam_policy" "ato_admin_policy" {
  name        = "ATOAdminPolicy"
  description = "Managed policy for ATOAdminRole permissions."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect" = "Allow",
        "Action" = [
          "autoscaling:*",
          "aws-portal:*",
          "budgets:ViewBudget",
          "config:Describe*",
          "config:Get*",
          "config:List*",
          "cloudformation:*",
          "cloudhsm:*",
          "cloudtrail:Describe*",
          "cloudtrail:Get*",
          "cloudtrail:Lookup*",
          "cloudwatch:*",
          "logs:*",
          "datapipeline:*",
          "directconnect:*",
          "dynamodb:*",
          "ec2:*",
          "ec2messages:*",
          "elasticache:*",
          "elasticloadbalancing:*",
          "elasticmapreduce:*",
          "es:*",
          "glacier:*",
          "iam:CreateServiceLinkedRole",
          "iam:DeleteServerCertificate",
          "iam:DeleteSigningCertificate",
          "iam:UpdateServerCertificate",
          "iam:UpdateSigningCertificate",
          "iam:UploadServerCertificate",
          "iam:UploadSigningCertificate",
          "iam:GenerateCredentialReport",
          "iam:Get*",
          "iam:List*",
          "kinesis:*",
          "kms:*",
          "aws-marketplace:*",
          "rds:*",
          "redshift:*",
          "s3:*",
          "sns:*",
          "sqs:*",
          "snowball:*",
          "ssm:*",
          "ssmmessages:*",
          "sts:DecodeAuthorizationMessage",
          "sts:AssumeRole",
          "sts:GetCallerIdentity",
          "support:*",
          "swf:*",
          "trustedadvisor:*",
          "workspaces:*",
          "dms:*",
          "ds:*",
          "states:*",
          "codedeploy:*",
          "lambda:*",
          "health:Describe*",
          "diode:*",
          "events:*",
          "ecs:*",
          "ecr:*",
          "sagemaker:*",
          "ec2:*ReservedInstances*",
          "events:*",
          "apigateway:*",
          "route53:*"
        ],
        "Resource" = "*"
      },
      {
        "Effect" = "Allow",
        "Action" = [
          "iam:PassRole"
        ],
        "Resource" = [
          "arn:${local.region_partition}:iam::*:role/INSTANCE*",
          "arn:${local.region_partition}:iam::*:role/LAMBDA*",
          "arn:${local.region_partition}:iam::*:role/snowball*",
          "arn:${local.region_partition}:iam::*:role/AFC2S*",
          "arn:${local.region_partition}:iam::*:role/workspaces*",
          "arn:${local.region_partition}:iam::*:role/service-role/*"
        ]
      },
      {
        "Effect" = "Allow",
        "Action" = [
          "iam:PassRole"
        ],
        "Resource" = "arn:${local.region_partition}:iam::*:role/INSTANCE*"
      },
      {
        "Effect" = "Allow",
        "Sid"    = "ATOAdminCreateAnyPolicy",
        "Action" = [
          "iam:CreatePolicy"
        ],
        "Resource" = "*"
      },
      {
        "Effect" = "Allow",
        "Sid"    = "ATOAdminCreateServiceRoles",
        "Action" = [
          "iam:AttachRolePolicy",
          "iam:CreateRole",
          "iam:PutRolePolicy"
        ],
        "Resource" = "arn:${local.region_partition}:iam::${local.caller_account_id}:role/service-role/*"
      },
    ]
  })
}

resource "aws_iam_policy" "ato_role_creator_policy" {
  name        = "ATORoleCreatorPolicy"
  description = "Managed policy to delegate role creation and enforce permissions boundary in an ATO'd cloud."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        "Effect" = "Allow",
        "Sid"    = "CustomPolicies",
        "Action" = [
          "iam:CreatePolicy*",
          "iam:DeletePolicy*",
          "iam:SetDefaultPolicyVersion",
          "iam:CreatePolicyVersion",
          "iam:DeletePolicyVersion"
        ],
        "Resource" = "arn:${local.region_partition}:iam::${local.caller_account_id}:policy/AFC2S*"
      },
      {
        "Effect" = "Allow",
        "Sid"    = "CreateCustomRolesEnforceBoundary",
        "Action" = [
          "iam:AttachRolePolicy",
          "iam:CreateRole",
          "iam:DetachRolePolicy",
          "iam:PutRolePermissionsBoundary",
          "iam:PutRolePolicy"
        ],
        "Resource" = "arn:${local.region_partition}:iam::${local.caller_account_id}:role/AFC2S*"
        # TODO
        # Condition:
        #   StringLike:
        #     'iam:PermissionsBoundary': !Sub 'arn:${RegionPartition}:iam::${AWS::AccountId}:policy/ATOAdminPolicy'
      },
      {
        "Effect" = "Allow",
        "Sid"    = "EditCustomRoles",
        "Action" = [
          "iam:DeleteRole",
          "iam:UpdateRole",
          "iam:TagRole",
          "iam:UpdateAssumeRolePolicy",
          "iam:DeleteRolePolicy",
          "iam:UntagRole"
        ],
        "Resource" = "arn:${local.region_partition}:iam::${local.caller_account_id}:role/AFC2S*"
      },
      {
        "Effect" = "Allow",
        "Sid"    = "CustomInstanceProfiles",
        "Action" = [
          "iam:AddRoleToInstanceProfile",
          "iam:CreateInstanceProfile",
          "iam:DeleteInstanceProfile",
          "iam:RemoveRoleFromInstanceProfile"
        ],
        "Resource" = "arn:${local.region_partition}:iam::${local.caller_account_id}:instance-profile/AFC2S*"
      }
    ]
  })
}




