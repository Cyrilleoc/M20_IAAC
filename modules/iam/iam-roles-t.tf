resource "aws_iam_role" "serv_admin_role" {
  name                 = "SERVADMIN"
  max_session_duration = var.role_timeout_settings

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          AWS = "arn:${local.region_partition}:iam::${var.cap_account}:root"
        }
      },
    ]
  })
  depends_on = [
    aws_iam_policy.serv_admin_policy
  ]
  managed_policy_arns = ["arn:${local.region_partition}:iam::${local.caller_account_id}:policy/ServAdminPolicy"]
}

resource "aws_iam_role" "clapper_role" {
  name                 = "CLAPPER"
  max_session_duration = var.role_timeout_settings

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.${local.region_root_url}"
        }
      },
    ]
  })
  depends_on = [
    aws_iam_policy.clapper_policy
  ]
  managed_policy_arns = ["arn:${local.region_partition}:iam::${local.caller_account_id}:policy/ClapperPolicy"]
}

resource "aws_iam_role" "net_admin_role" {
  name                 = "NETADMIN"
  max_session_duration = var.role_timeout_settings

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          AWS = "arn:${local.region_partition}:iam::${var.cap_account}:root"
        }
      },
    ]
  })
  depends_on = [
    aws_iam_policy.net_admin_policy
  ]
  managed_policy_arns = ["arn:${local.region_partition}:iam::${local.caller_account_id}:policy/NetAdminPolicy"]
}

resource "aws_iam_role" "prov_admin_role" {
  name                 = "PROVADMIN"
  max_session_duration = var.role_timeout_settings

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          AWS = "arn:${local.region_partition}:iam::${var.cap_account}:root"
        }
      },
    ]
  })
  depends_on = [
    aws_iam_policy.prov_admin_policy
  ]
  managed_policy_arns = ["arn:${local.region_partition}:iam::${local.caller_account_id}:policy/ProvAdminPolicy"]
}

resource "aws_iam_role" "CNDIS_role" {
  name                 = "CNDIS"
  max_session_duration = var.role_timeout_settings

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          AWS = "arn:${local.region_partition}:iam::${var.cap_account}:root"
        }
      },
    ]
  })
  depends_on = [
    aws_iam_policy.CNDIS_policy
  ]
  managed_policy_arns = ["arn:${local.region_partition}:iam::${local.caller_account_id}:policy/CNDISPolicy"]
}

resource "aws_iam_role" "CNDIS_readonly_role" {
  name                 = "CNDISREADONLY"
  max_session_duration = var.role_timeout_settings

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          AWS = "arn:${local.region_partition}:iam::${var.cap_account}:root"
        }
      },
    ]
  })
  depends_on = [
    aws_iam_policy.CNDIS_readonly_policy
  ]
  managed_policy_arns = ["arn:${local.region_partition}:iam::${local.caller_account_id}:policy/CNDISReadOnlyPolicy"]
}

resource "aws_iam_role" "marketplace_role" {
  name                 = "MARKETPLACE"
  max_session_duration = var.role_timeout_settings

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          AWS = "arn:${local.region_partition}:iam::${var.cap_account}:root"
        }
      },
    ]
  })
  depends_on = [
    aws_iam_policy.marketplace_policy
  ]
  managed_policy_arns = ["arn:${local.region_partition}:iam::${local.caller_account_id}:policy/MarketplacePolicy"]
}

resource "aws_iam_role" "business_role" {
  name                 = "BUSINESS"
  max_session_duration = var.role_timeout_settings

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          AWS = "arn:${local.region_partition}:iam::${var.cap_account}:root"
        }
      },
    ]
  })
  depends_on = [
    aws_iam_policy.business_policy
  ]
  managed_policy_arns = ["arn:${local.region_partition}:iam::${local.caller_account_id}:policy/BusinessPolicy"]
}

resource "aws_iam_role" "tech_readonly_role" {
  name                 = "TECHREADONLY"
  max_session_duration = var.role_timeout_settings

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          AWS = "arn:${local.region_partition}:iam::${var.cap_account}:root"
        }
      },
    ]
  })
  depends_on = [
    aws_iam_policy.tech_readonly_policy
  ]
  managed_policy_arns = ["arn:${local.region_partition}:iam::${local.caller_account_id}:policy/TechReadOnlyPolicy"]
}

resource "aws_iam_role" "proj_admin_role" {
  name                 = "PROJADMIN"
  max_session_duration = var.role_timeout_settings

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          AWS = "arn:${local.region_partition}:iam::${var.cap_account}:root"
        }
      },
    ]
  })
  depends_on = [
    aws_iam_policy.proj_admin_policy,
    aws_iam_policy.role_creator_policy
  ]
  managed_policy_arns = [
    "arn:${local.region_partition}:iam::${local.caller_account_id}:policy/ProjAdminPolicy",
    "arn:${local.region_partition}:iam::${local.caller_account_id}:policy/RoleCreatorPolicy"
  ]
}

resource "aws_iam_role" "dev_admin_role" {
  name                 = "DEVADMIN"
  max_session_duration = var.role_timeout_settings

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          AWS = "arn:${local.region_partition}:iam::${var.cap_account}:root"
        }
      },
    ]
  })
  depends_on = [
    aws_iam_policy.dev_admin_policy
  ]
  managed_policy_arns = ["arn:${local.region_partition}:iam::${local.caller_account_id}:policy/DevAdminPolicy"]
}

resource "aws_iam_role" "proj_admin_limited_role" {
  name                 = "PROJADMINLIMITED"
  max_session_duration = var.role_timeout_settings

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          AWS = "arn:${local.region_partition}:iam::${var.cap_account}:root"
        }
      },
    ]
  })
  depends_on = [
    aws_iam_policy.proj_admin_limited_policy
  ]
  managed_policy_arns = ["arn:${local.region_partition}:iam::${local.caller_account_id}:policy/ProjAdminLimitedPolicy"]
}

resource "aws_iam_role" "storage_role" {
  name                 = "STORAGE"
  max_session_duration = var.role_timeout_settings

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          AWS = "arn:${local.region_partition}:iam::${var.cap_account}:root"
        }
      },
    ]
  })
  depends_on = [
    aws_iam_policy.storage_policy
  ]
  managed_policy_arns = ["arn:${local.region_partition}:iam::${local.caller_account_id}:policy/StoragePolicy"]
}

resource "aws_iam_role" "database_role" {
  name                 = "DATABASE"
  max_session_duration = var.role_timeout_settings

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          AWS = "arn:${local.region_partition}:iam::${var.cap_account}:root"
        }
      },
    ]
  })
  depends_on = [
    aws_iam_policy.database_policy
  ]
  managed_policy_arns = ["arn:${local.region_partition}:iam::${local.caller_account_id}:policy/DatabasePolicy"]
}

resource "aws_iam_role" "s3_only_role" {
  name                 = "S3ONLY"
  max_session_duration = var.role_timeout_settings

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          AWS = "arn:${local.region_partition}:iam::${var.cap_account}:root"
        }
      },
    ]
  })
  depends_on = [
    aws_iam_policy.s3_only_policy
  ]
  managed_policy_arns = ["arn:${local.region_partition}:iam::${local.caller_account_id}:policy/S3OnlyPolicy"]
}

resource "aws_iam_role" "key_manager_role" {
  name                 = "KEYMANAGER"
  max_session_duration = var.role_timeout_settings

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          AWS = "arn:${local.region_partition}:iam::${var.cap_account}:root"
        }
      },
    ]
  })
  depends_on = [
    aws_iam_policy.key_manager_policy
  ]
  managed_policy_arns = ["arn:${local.region_partition}:iam::${local.caller_account_id}:policy/KeyManagerPolicy"]
}

resource "aws_iam_role" "emr_service_role" {
  name                 = "EMRSERVICE"
  max_session_duration = var.role_timeout_settings

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.${local.region_root_url}"
        }
      },
    ]
  })
  depends_on = [
    aws_iam_policy.emr_service_policy
  ]
  managed_policy_arns = ["arn:${local.region_partition}:iam::${local.caller_account_id}:policy/EMRServicePolicy"]
}

resource "aws_iam_role" "instance_emr_role" {
  name                 = "INSTANCEEMR"
  max_session_duration = var.role_timeout_settings

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.${local.region_root_url}"
        }
      },
    ]
  })
  depends_on = [
    aws_iam_policy.instance_emr_policy
  ]
  managed_policy_arns = ["arn:${local.region_partition}:iam::${local.caller_account_id}:policy/InstanceEMRPolicy"]
}

resource "aws_iam_role" "instance_role" {
  name                 = "INSTANCE"
  max_session_duration = var.role_timeout_settings

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.${local.region_root_url}"
        }
      },
    ]
  })
  depends_on = [
    aws_iam_policy.instance_policy
  ]
  managed_policy_arns = ["arn:${local.region_partition}:iam::${local.caller_account_id}:policy/InstancePolicy"]
}

resource "aws_iam_role" "config_manager_role" {
  name                 = "CONFIGMANAGER"
  max_session_duration = var.role_timeout_settings

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          AWS = "arn:${local.region_partition}:iam::${var.cap_account}:root"
        }
      },
    ]
  })
  depends_on = [
    aws_iam_policy.config_manager_policy
  ]
  managed_policy_arns = ["arn:${local.region_partition}:iam::${local.caller_account_id}:policy/ConfigManagerPolicy"]
}

resource "aws_iam_role" "config_role" {
  name                 = "CONFIG"
  max_session_duration = var.role_timeout_settings

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          AWS = "arn:${local.region_partition}:iam::${var.cap_account}:root"
        }
      },
    ]
  })
  depends_on = [
    aws_iam_policy.config_policy
  ]
  managed_policy_arns = ["arn:${local.region_partition}:iam::${local.caller_account_id}:policy/ConfigPolicy"]
}

resource "aws_iam_role" "pipeline_service_role" {
  name                 = "PIPELINESERVICE"
  max_session_duration = var.role_timeout_settings

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.${local.region_root_url}"
        }
      },
    ]
  })
  depends_on = [
    aws_iam_policy.pipeline_service_policy
  ]
  managed_policy_arns = ["arn:${local.region_partition}:iam::${local.caller_account_id}:policy/PipelineServicePolicy"]
}

resource "aws_iam_role" "instance_pipeline_role" {
  name                 = "INSTANCEPIPELINE"
  max_session_duration = var.role_timeout_settings

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.${local.region_root_url}"
        }
      },
    ]
  })
  depends_on = [
    aws_iam_policy.instance_pipeline_policy
  ]
  managed_policy_arns = ["arn:${local.region_partition}:iam::${local.caller_account_id}:policy/InstancePipelinePolicy"]
}

resource "aws_iam_role" "ent_eng_role" {
  name                 = "ENTENG"
  max_session_duration = var.role_timeout_settings

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          AWS = "arn:${local.region_partition}:iam::${var.cap_account}:root"
        }
      },
    ]
  })
  depends_on = [
    aws_iam_policy.ent_eng_policy
  ]
  managed_policy_arns = ["arn:${local.region_partition}:iam::${local.caller_account_id}:policy/EntEngPolicy"]
}

resource "aws_iam_role" "sec_eng_role" {
  name                 = "SECENG"
  max_session_duration = var.role_timeout_settings

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          AWS = "arn:${local.region_partition}:iam::${var.cap_account}:root"
        }
      },
    ]
  })
  depends_on = [
    aws_iam_policy.sec_eng_policy
  ]
  managed_policy_arns = [
    "arn:${local.region_partition}:iam::${local.caller_account_id}:policy/SecEngPolicy",
    "arn:${local.region_partition}:iam::aws:policy/ReadOnlyAccess"
  ]
}

resource "aws_iam_role" "instance_s3_role" {
  name                 = "AFC2S_INSTANCE_S3"
  max_session_duration = var.role_timeout_settings

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.${local.region_root_url}"
        }
      },
    ]
  })
  depends_on = [
    aws_iam_policy.s3_only_policy
  ]
  managed_policy_arns = ["arn:${local.region_partition}:iam::${local.caller_account_id}:policy/S3OnlyPolicy"]
}

resource "aws_iam_instance_profile" "instance_s3_profile" {
  name = aws_iam_role.instance_s3_role.name
  path = "/"
  role = aws_iam_role.instance_s3_role.name
  depends_on = [
    aws_iam_role.instance_s3_role
  ]
}

resource "aws_iam_role" "afc2s_business_role" {
  name                 = "BIZENT"
  max_session_duration = var.role_timeout_settings

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          AWS = "arn:${local.region_partition}:iam::${var.cap_account}:root"
        }
      },
    ]
  })

  depends_on = [
    aws_iam_policy.ent_business_policy
  ]
  managed_policy_arns = [
    "arn:${local.region_partition}:iam::${local.caller_account_id}:policy/EntBusinessPolicy"
  ]
}

resource "aws_iam_role" "ato_admin_jwics_role" {
  name                 = "ATOADMIN"
  max_session_duration = var.role_timeout_settings

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          AWS = "arn:${local.region_partition}:iam::${var.cap_account}:root"
        }
      },
    ]
  })

  depends_on = [
    aws_iam_policy.ato_admin_policy,
    aws_iam_policy.ato_role_creator_policy
  ]
  managed_policy_arns = [
    "arn:${local.region_partition}:iam::${local.caller_account_id}:policy/ATOAdminPolicy",
    "arn:${local.region_partition}:iam::${local.caller_account_id}:policy/ATORoleCreatorPolicy"
  ]
}

resource "aws_iam_role" "workspaces_service_role" {
  name                 = "workspaces_DefaultRole"
  max_session_duration = var.role_timeout_settings

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = "workspacesrole"
        Principal = {
          Service = "workspaces.${local.region_root_url}"
        }
      },
    ]
  })
  path = "/"
  inline_policy {
    name = "WorkSpacesServiceAccess"

    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Action = [
            "ec2:CreateNetworkInterface",
            "ec2:DeleteNetworkInterface",
            "ec2:DescribeNetworkInterfaces",
            "ds:DescribeDomains"
          ]
          Effect   = "Allow"
          Resource = "*"
        },
      ]
    })
  }
}

