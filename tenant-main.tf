
resource "aws_vpc" "tenant_vpc" {
  cidr_block           = var.tenant_cidr # !Ref pTenantCIDR
  instance_tenancy     = var.vpc_tenancy # !Ref pVPCTenancy
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name        = join(" ", [var.tenant_vpc_name, var.tenant_vpc_environment, "Tenant VPC"])
    Environment = var.tenant_vpc_environment
  }
}

# this is not part of cloudformation template, for demo purpose only
resource "aws_subnet" "tenant_public_subnet" {
  vpc_id     = aws_vpc.tenant_vpc.id
  cidr_block = "10.0.1.0/24"

  map_public_ip_on_launch = true // it makes this a public subnet
  availability_zone       = "us-east-1a"
  tags = {
    Name = "tenant_public_subnet"
  }
}

resource "aws_route_table" "tenant_route_table" {
  vpc_id = aws_vpc.tenant_vpc.id

  # DestinationCidrBlock: !Ref pTransitVPCCIDR
  # RouteTableId: !Ref rRouteTableMain
  # VpcPeeringConnectionId: !Ref rVPCPeeringConnection

  # routes not defined as there is transit account is not provisioned yet
  # route = []

  # route {
  #   cidr_block = "10.0.1.0/24"
  #   gateway_id = aws_internet_gateway.example.id
  # }


  tags = {
    Name = join(" ", [var.tenant_vpc_name, var.tenant_vpc_environment, "Tenant VPC Route Table"])
  }
}

# resource "aws_vpc_peering_connection" "vpc_peering_connection" {
#   peer_owner_id = var.peer_vpc_account_id
#   peer_vpc_id   = var.peer_vpc_id
#   vpc_id        = aws_vpc.tenant_vpc.id
# }

resource "aws_vpc_endpoint" "tenant_vpc_endpoint" {
  vpc_id          = aws_vpc.tenant_vpc.id
  route_table_ids = [aws_route_table.tenant_route_table.id]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action    = "*"
        Effect    = "Allow"
        Principal = "*"
        Resource  = "*"
      },
    ]
  })

  # ServiceName: !Join
  #     - ''
  #     - - com.amazonaws.
  #     - !Ref 'AWS::Region'
  #     - .s3
  service_name = "com.amazonaws.us-east-1.s3"

}

#### FLOW LOG ######

resource "aws_iam_role" "tenant_vpc_flow_logs_service_role" {
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = "AllowFlowLogs"
        Principal = {
          #VPC Flow Logs uses the same URL suffix in all regions
          Service = "vpc-flow-logs.amazonaws.com"
        }
      },
    ]
  })
  path = "/"
  inline_policy {
    name = "cloudwatchlogsrole"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          "Effect" : "Allow",
          "Action" : [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
            "logs:DescribeLogGroups",
            "logs:DescribeLogStreams"
          ],
          "Resource" : "*"
        }
      ]
    })
  }
}

resource "aws_cloudwatch_log_group" "tenant_vpc_log_group" {
  name = "tenant_vpc_log_group"
}

resource "aws_flow_log" "tenant_vpc_flowlog" {
  iam_role_arn    = aws_iam_role.tenant_vpc_flow_logs_service_role.arn
  log_destination = aws_cloudwatch_log_group.tenant_vpc_log_group.arn # not sure about this
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.tenant_vpc.id
}


#### S3 BUCKET ######
resource "aws_s3_bucket" "lambda_tenant_bucket" {
  bucket = var.tenant_bucket_name
}

resource "aws_s3_bucket_notification" "lambda_tenant_bucket_notification" {
  bucket = aws_s3_bucket.lambda_tenant_bucket.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.lambda_move_pub_keys.arn
    events              = ["s3:ObjectCreated:*", "s3:ObjectRemoved:*"]
    filter_suffix       = ".pub"
  }

  depends_on = [aws_lambda_permission.lambda_processing_permission]
}

#### LAMBDA ######

resource "aws_iam_policy" "lambda_move_pub_keys_policy" {
  name = "LambdaMovePubKeysPolicy"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      # TODO: lambda_move_pub_keys_xist_role check this.
      # {
      #   Sid = "LambdaMovePubKeysAssumeRole"
      #   Action = [
      #     "sts:AssumeRole"
      #   ]
      #   Effect   = "Allow"
      #   Resource = "${var.lambda_move_pub_keys_xist_role}"
      # },
      {
        Sid = "LambdaMovePubKeysS3Read"
        Action = [
          "s3:GetObject"
        ]
        Effect = "Allow"
        Resource = [
          "arn:${local.region_partition}:s3:::${var.tenant_bucket_name}",
          "arn:${local.region_partition}:s3:::${var.tenant_bucket_name}/*"
        ]
      },
      {
        Sid = "LambdaMovePubKeysLogAccess"
        Action = [
          "logs:CreateLogStreams",
          "logs:PutLogEvents"
        ]
        Effect   = "Allow"
        Resource = "arn:${local.region_partition}:logs:us-iso-east-1:${local.caller_account_id}:log-group:/aws/lambda/lambdaMovePublicKeys:*"
      },
      {
        Sid = "LambdaMovePubKeysCreateLogGroup"
        Action = [
          "logs:CreateLogGroup"
        ]
        Effect   = "Allow"
        Resource = "arn:${local.region_partition}:logs:us-iso-east-1:${local.caller_account_id}:*"
      }
    ]
  })
}

resource "aws_lambda_permission" "lambda_processing_permission" {
  action         = "lambda:InvokeFunction"
  function_name  = aws_lambda_function.lambda_move_pub_keys.function_name
  principal      = "s3.amazonaws.com"
  source_arn     = "arn:${local.region_partition}:s3:::${var.tenant_bucket_name}"
  source_account = local.caller_account_id
}

resource "aws_iam_role" "lambda_move_pub_keys_role" {
  name                 = "LambdaMovePubKeysRole"
  max_session_duration = "4600"

  # Terraform's "jsonencode" function converts a
  # Terraform expression result to valid JSON syntax.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.${local.region_root_url}"
        }
      },
    ]
  })
  depends_on          = [aws_iam_policy.lambda_move_pub_keys_policy]
  managed_policy_arns = ["arn:${local.region_partition}:iam::${local.caller_account_id}:policy/LambdaMovePubKeysPolicy"]
  # ManagedPolicyArns:
  # - !Sub 'arn:${RegionPartition}:iam::${AWS::AccountId}:policy/LambdaMovePubKeysPolicy'
}

resource "aws_lambda_function" "lambda_move_pub_keys" {
  description   = "Manages Public Keys For BastionHost"
  function_name = "lambdaMovePublicKeys"
  role          = aws_iam_role.lambda_move_pub_keys_role.arn
  handler       = "move_bastion_keys.lambda_handler"

  s3_bucket = var.template_origin_bucket
  s3_key    = var.lambda_key

  runtime = "python3.7"
  timeout = 300
}



