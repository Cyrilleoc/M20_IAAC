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
