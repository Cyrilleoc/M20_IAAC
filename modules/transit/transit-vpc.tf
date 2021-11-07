# VPC
resource "aws_vpc" "transit_vpc" {
  cidr_block           = var.transit_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = var.transit_vpc_name
  }
}

##### SECURITY GROUPS
resource "aws_security_group" "security_group_proxy_elb" {
  description = "Allow Proxy Traffic to ELB from Transit VPC"
  vpc_id      = aws_vpc.transit_vpc.id

  ingress {
    description = "HTTP traffic from Transit"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = [var.transit_cidr]
  }
  ingress {
    description = "HTTPS traffic from Transit"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.transit_cidr]
  }
  ingress {
    description = "Squid traffic from Transit"
    from_port   = 3128
    to_port     = 3128
    protocol    = "tcp"
    cidr_blocks = [var.transit_cidr]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name        = "sg-web-proxy-ports-to-elb"
    Environment = var.environment
  }
}

resource "aws_security_group" "security_group_bastion" {
  description = "SG for Bastion Instance"
  vpc_id      = aws_vpc.transit_vpc.id

  ingress {
    description = "SSH connection traffic"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.bastion_ssh_cidr]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name        = "sg-ssh-access-to-bastion"
    Environment = var.environment
  }
}

resource "aws_security_group" "security_group_proxy_instance" {
  description = "Allow Proxy and SSH Traffic from ELB/Bastion to Instance(s)"
  depends_on = [
    aws_security_group.security_group_proxy_elb,
    aws_security_group.security_group_bastion
  ]
  vpc_id = aws_vpc.transit_vpc.id

  ingress {
    description     = "Squid traffic"
    from_port       = 3128
    to_port         = 3128
    protocol        = "tcp"
    security_groups = [aws_security_group.security_group_proxy_elb.id]
  }
  ingress {
    description     = "SSH connection traffic"
    from_port       = 22
    to_port         = 22
    protocol        = "tcp"
    security_groups = [aws_security_group.security_group_bastion.id]
  }
  ingress {
    description = "NTP traffic"
    from_port   = 123
    to_port     = 123
    protocol    = "udp"
    cidr_blocks = ["10.0.0.0/16"]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name        = "sg-web-proxy-ports-to-instances"
    Environment = var.environment
  }
}

resource "aws_security_group" "security_group_ssh_from_transit" {
  description = "Enable SSH access via port 22"
  vpc_id      = aws_vpc.transit_vpc.id

  ingress {
    description = "SSH connection traffic"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.transit_cidr]
  }

  egress {
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name        = "sg-ssh-access-from-transit-vpc"
    Environment = var.environment
  }
}

####### SUBNET
resource "aws_subnet" "transit_dmz_subnet_A" {
  vpc_id            = aws_vpc.transit_vpc.id
  cidr_block        = var.transit_dmz_subnet_A_cidr
  availability_zone = var.region_az1_name
  tags = {
    Name = "Transit DMZ Subnet A"
  }
}

resource "aws_subnet" "transit_dmz_subnet_B" {
  vpc_id            = aws_vpc.transit_vpc.id
  cidr_block        = var.transit_dmz_subnet_B_cidr
  availability_zone = var.region_az2_name
  tags = {
    Name = "Transit DMZ Subnet B"
  }
}

resource "aws_subnet" "transit_private_subnet_A" {
  vpc_id            = aws_vpc.transit_vpc.id
  cidr_block        = var.transit_private_subnet_A_cidr
  availability_zone = var.region_az1_name
  tags = {
    Name = "Transit Private Subnet A"
  }
}

resource "aws_subnet" "transit_private_subnet_B" {
  vpc_id            = aws_vpc.transit_vpc.id
  cidr_block        = var.transit_private_subnet_B_cidr
  availability_zone = var.region_az2_name
  tags = {
    Name = "Transit Private Subnet B"
  }
}

#### INTERNET GATEWAY
resource "aws_internet_gateway" "transit_igw" {
  vpc_id = aws_vpc.transit_vpc.id

  tags = {
    Name = "igw-transit"
  }
}

#### ROUTE TABLE
resource "aws_route_table" "transit_private_route_table" {
  vpc_id = aws_vpc.transit_vpc.id

  tags = {
    Name = "Transit Private Route"
  }
}

resource "aws_route_table" "transit_dmz_route_table" {
  vpc_id = aws_vpc.transit_vpc.id

  tags = {
    Name        = "Transit DMZ Route"
    Description = join(" ", [var.transit_vpc_name, var.environment, "Transit VPC DMZ Route"])
  }
}

resource "aws_route" "route_transit_igw" {
  route_table_id         = aws_route_table.transit_dmz_route_table.id
  gateway_id             = aws_internet_gateway.transit_igw.id
  destination_cidr_block = "0.0.0.0/0"
}

###### ROUTE TABLE ASSOCIATION
resource "aws_route_table_association" "route_assoc_transit_dmz_A" {
  subnet_id      = aws_subnet.transit_dmz_subnet_A.id
  route_table_id = aws_route_table.transit_dmz_route_table.id
}

resource "aws_route_table_association" "route_assoc_transit_dmz_B" {
  subnet_id      = aws_subnet.transit_dmz_subnet_B.id
  route_table_id = aws_route_table.transit_dmz_route_table.id
}

resource "aws_route_table_association" "route_assoc_transit_private_A" {
  subnet_id      = aws_subnet.transit_private_subnet_A.id
  route_table_id = aws_route_table.transit_private_route_table.id
}

resource "aws_route_table_association" "route_assoc_transit_private_B" {
  subnet_id      = aws_subnet.transit_private_subnet_B.id
  route_table_id = aws_route_table.transit_private_route_table.id
}

####### VPC ENDPOINT
resource "aws_vpc_endpoint" "transit_vpc_endpoint" {
  depends_on = [
    aws_vpc.transit_vpc,
    aws_route_table.transit_dmz_route_table,
    aws_route_table.transit_private_route_table
  ]

  vpc_id = aws_vpc.transit_vpc.id

  route_table_ids = [
    aws_route_table.transit_dmz_route_table.id,
    aws_route_table.transit_private_route_table.id
  ]

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

  service_name = "com.amazonaws.${local.caller_aws_region}.s3"
}

#### IAM ROLE
resource "aws_iam_role" "transit_log_role" {
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
  path = "/"
  inline_policy {
    name = "LogRolePolicy"

    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Action = [
            "logs:Create*",
            "logs:PutLogEvents"
          ]
          Effect   = "Allow"
          Resource = "arn:${var.region_partition}:logs:*:*:*"
        },
        {
          Action   = "s3:GetObject"
          Effect   = "Allow"
          Resource = "arn:${var.region_partition}:s3:::${var.config_bucket}/*"
        }
      ]
    })
  }
}

resource "aws_iam_role" "bastion_host_role" {
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
  path = "/"
  inline_policy {
    name = "LogRolePolicy"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Action = [
            "logs:Create*",
            "logs:PutLogEvents"
          ]
          Effect   = "Allow"
          Resource = "arn:${var.region_partition}:logs:*:*:*"
        }
      ]
    })
  }

  inline_policy {
    name   = "BastionPolicy"
    policy = data.aws_iam_policy_document.bastion_role_inline_policy.json
  }
}

resource "aws_iam_role" "transit_vpc_flow_logs_service_role" {
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowFlowLogs"
        Action = "sts:AssumeRole"
        Effect = "Allow"
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
          Action = [
            "logs:CreateLogGroup",
            "logs:CreateLogStream",
            "logs:PutLogEvents",
            "logs:DescribeLogGroups",
            "logs:DescribeLogStreams"
          ]
          Effect   = "Allow"
          Resource = "*"
        }
      ]
    })
  }
}

resource "aws_iam_role" "peer_role" {
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "ec2.${local.region_root_url}"
        }
      },
    ]
  })
  path = "/"
  inline_policy {
    name = "requestvpcpeering"
    policy = jsonencode({
      Version = "2012-10-17"
      Statement = [
        {
          Action = [
            "ec2:AcceptVpcPeeringConnection"
          ]
          Effect   = "Allow"
          Resource = "*"
        }
      ]
    })
  }
}

resource "aws_iam_role" "lambda_move_pub_keys_xsit_role" {
  name                 = "LambdaMovePubKeysXsitRole"
  max_session_duration = "4600"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${var.region_partition}:iam::${var.tenant_account_id}:root"
        }
      },
    ]
  })
  depends_on          = [aws_iam_policy.transit_read_only_policy]
  managed_policy_arns = ["arn:${var.region_partition}:iam::${local.caller_account_id}:policy/LambdaMovePubKeysXsitPolicy"]
}

resource "aws_iam_role" "transit_read_only_jwics_role" {
  count                = local.jwics_resource ? 1 : 0
  name                 = "TRANSITREADONLY"
  max_session_duration = "43200"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = ""
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          AWS = "arn:${var.region_partition}:iam::${var.cap_account}:root"
        }
      },
    ]
  })
  depends_on          = [aws_iam_policy.transit_read_only_policy]
  managed_policy_arns = ["arn:${var.region_partition}:iam::${local.caller_account_id}:policy/TransitReadOnlyPolicy"]
}

resource "aws_iam_role" "transit_read_only_sipr_role" {
  count                = local.sipr_resource ? 1 : 0
  name                 = "TRANSITREADONLY"
  max_session_duration = "43200"
  assume_role_policy   = data.aws_iam_policy_document.transit_geoaxis_saml_policy.json
  depends_on           = [aws_iam_policy.transit_read_only_policy]
  managed_policy_arns  = ["arn:${var.region_partition}:iam::${local.caller_account_id}:policy/TransitReadOnlyPolicy"]
}

resource "aws_iam_role" "transit_read_only_nipr_role" {
  count                = local.nipr_resource ? 1 : 0
  name                 = "TRANSITREADONLY"
  max_session_duration = "43200"
  assume_role_policy   = data.aws_iam_policy_document.transit_geoaxis_saml_policy.json
  depends_on           = [aws_iam_policy.transit_read_only_policy]
  managed_policy_arns  = ["arn:${var.region_partition}:iam::${local.caller_account_id}:policy/TransitReadOnlyPolicy"]
}

resource "aws_iam_role" "transit_read_only_gov_role" {
  count                = local.gov_cloud_resource ? 1 : 0
  name                 = "TRANSITREADONLY"
  max_session_duration = "43200"
  assume_role_policy   = data.aws_iam_policy_document.transit_geoaxis_saml_policy.json
  depends_on           = [aws_iam_policy.transit_read_only_policy]
  managed_policy_arns  = ["arn:${var.region_partition}:iam::${local.caller_account_id}:policy/TransitReadOnlyPolicy"]
}

##### INSTANCE PROFILE
resource "aws_iam_instance_profile" "transit_log_role_instance_profile" {
  path = "/"
  role = aws_iam_role.transit_log_role.name
}

resource "aws_iam_instance_profile" "bastion_host_profile" {
  path = "/"
  role = aws_iam_role.bastion_host_role.name
}

##### AUTOSCALING GROUP
resource "aws_eip" "eip_bastion" {
  # instance = aws_instance.web.id
  vpc = true
}

resource "aws_launch_configuration" "autoscaling_group_config_bastion" {
  depends_on = [
    aws_eip.eip_bastion,
    aws_iam_instance_profile.bastion_host_profile,
    aws_security_group.security_group_bastion
  ]
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.bastion_host_profile.name
  image_id                    = var.bastion_ami
  instance_type               = var.bastion_instance_type
  key_name                    = var.bastion_key_pair
  security_groups             = [aws_security_group.security_group_bastion.id]
  ## TODO: Check how to add user_data
  # user_data= <<EOT
  # #!/bin/bash -x

  # # Install Dependencies
  # yum install unzip -y

  # # Install AWS CLI
  # curl "http://${pAwsCliUrl}/awscli-bundle.zip" -o "awscli-bundle.zip"
  # unzip awscli-bundle.zip
  # ./awscli-bundle/install -b /bin/aws
  # export AWS_CA_BUNDLE=/etc/pki/tls/certs/ca-bundle.crt
  # echo 'export AWS_CA_BUNDLE=/etc/pki/tls/certs/ca-bundle.crt' >> ~/.bashrc
  # export AWS_DEFAULT_REGION=${AWS::Region}
  # echo 'export AWS_DEFAULT_REGION=${AWS::Region}' >> ~/.bashrc

  # # Configure Bastion Instance
  # instance_id=$(curl -s http://169.254.169.254/latest/meta-data/instance-id)
  # aws ec2 associate-address --allocation-id ${rEIPBastion.AllocationId} --instance-id ${!instance_id} --allow-reassociation --region ${AWS::Region}
  # export AWS_DEFAULT_REGION=${AWS::Region}
  # aws s3 cp s3://${pConfigBucket}/bastion_userdata.sh .
  # chmod 700 bastion_userdata.sh
  # ./bastion_userdata.sh ${!instance_id} ${pLogsBucket} ${AWS::Region} ${AWS::StackName}

  # # Configure Cloudwatch Logs Agent
  # curl -O ${BuildS3URL}/amazoncloudwatch-agent/redhat/amd64/latest/amazon-cloudwatch-agent.rpm
  # rpm -ivh amazon-cloudwatch-agent.rpm
  # touch /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
  # JSON_STRING="{\"logs\":{\"logs_collected\":{\"files\":{\"collect_list\":[{\"file_path\":\"/var/log/secure\",\"log_group_name\":\"/var/log/secure\",\"log_stream_name\":\"${!instance_id}\",\"timestamp_format\":\"%b-%d-%y--%H:%M:%S\"},{\"file_path\":\"/var/log/messages\",\"log_group_name\":\"/var/log/messages\",\"log_stream_name\":\"${!instance_id}\",\"timestamp_format\":\"%b-%d-%y--%H:%M:%S\"}]}},\"log_stream_name\":\"${!instance_id}\"}}"
  # echo $JSON_STRING > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
  # /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s
  # EOT
}

resource "aws_autoscaling_group" "autoscaling_group_bastion" {
  depends_on = [
    aws_launch_configuration.autoscaling_group_config_bastion
  ]
  # NOTE: availability_zones is excluded as it Conflicts with vpc_zone_identifier
  # availability_zones = [
  #   var.region_az1_name,
  #   var.region_az2_name
  # ]
  vpc_zone_identifier = [
    aws_subnet.transit_dmz_subnet_A.id,
    aws_subnet.transit_dmz_subnet_B.id
  ]
  launch_configuration      = aws_launch_configuration.autoscaling_group_config_bastion.name
  max_size                  = var.bastion_auto_scale_max
  min_size                  = var.bastion_auto_scale_min
  health_check_grace_period = 300
  health_check_type         = "EC2"
  tags = concat(
    [
      {
        "key"                 = "Name"
        "value"               = "BastionServer"
        "propagate_at_launch" = true
      },
      {
        "key"                 = "Environment"
        "value"               = var.environment
        "propagate_at_launch" = true
      },
    ]
  )
}

resource "aws_launch_configuration" "autoscaling_group_config_proxy" {
  depends_on = [
    aws_elb.elb_proxy,
    aws_security_group.security_group_proxy_instance
  ]
  associate_public_ip_address = true
  iam_instance_profile        = aws_iam_instance_profile.transit_log_role_instance_profile.name
  image_id                    = var.proxy_ami
  instance_type               = var.proxy_instance_type
  key_name                    = var.proxy_key_pair
  security_groups             = [aws_security_group.security_group_proxy_instance.id]
  ## TODO: Check how to add user_data
  # user_data = <<EOT
  # #!/bin/bash -x

  # # Install Dependencies
  # yum install unzip -y
  # yum install squid -y
  # chkconfig squid on
  # service squid start

  # # Install AWS CLI
  # curl "http://${pAwsCliUrl}/awscli-bundle.zip" -o "awscli-bundle.zip"
  # unzip awscli-bundle.zip
  # ./awscli-bundle/install -b /bin/aws
  # export AWS_CA_BUNDLE=/etc/pki/tls/certs/ca-bundle.crt
  # echo 'export AWS_CA_BUNDLE=/etc/pki/tls/certs/ca-bundle.crt' >> ~/.bashrc
  # export AWS_DEFAULT_REGION=${AWS::Region}
  # echo 'export AWS_DEFAULT_REGION=${AWS::Region}' >> ~/.bashrc

  # # Configure Squid Proxy
  # cd /etc/squid
  # aws s3 cp s3://${pConfigBucket}/baseline-domain.txt .
  # aws s3 cp s3://${pConfigBucket}/baseline-ip.txt .
  # aws s3 cp s3://${pConfigBucket}/custom-domain.txt .
  # aws s3 cp s3://${pConfigBucket}/custom-ip.txt .
  # mv squid.conf squid.conf.bak
  # aws s3 cp s3://${pConfigBucket}/squid.conf .
  # chown squid:squid baseline-domain.txt
  # chown squid:squid baseline-ip.txt
  # chown squid:squid custom-domain.txt
  # chown squid:squid custom-ip.txt
  # aws s3 cp s3://${pConfigBucket}/chrony.conf /etc/chrony.conf
  # service squid restart
  # cd /etc/cron.hourly
  # aws s3 cp s3://${pConfigBucket}/updateproxy.sh .
  # chmod +x updateproxy.sh

  # # Configure Cloudwatch Logs Agent
  # curl -O ${BuildS3URL}/amazoncloudwatch-agent/redhat/amd64/latest/amazon-cloudwatch-agent.rpm
  # rpm -ivh amazon-cloudwatch-agent.rpm
  # touch /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
  # JSON_STRING="{\"logs\":{\"logs_collected\":{\"files\":{\"collect_list\":[{\"file_path\":\"/var/log/squid/access.log\",\"log_group_name\":\"/var/log/squid/access\",\"log_stream_name\":\"${!instance_id}\",\"timestamp_format\":\"%b-%d-%y--%H:%M:%S\"},{\"file_path\":\"/var/log/secure\",\"log_group_name\":\"/var/log/secure\",\"log_stream_name\":\"${!instance_id}\",\"timestamp_format\":\"%b-%d-%y--%H:%M:%S\"},{\"file_path\":\"/var/log/messages\",\"log_group_name\":\"/var/log/messages\",\"log_stream_name\":\"${!instance_id}\",\"timestamp_format\":\"%b-%d-%y--%H:%M:%S\"}]}},\"log_stream_name\":\"${!instance_id}\"}}"
  # echo $JSON_STRING > /opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json
  # /opt/aws/amazon-cloudwatch-agent/bin/amazon-cloudwatch-agent-ctl -a fetch-config -m ec2 -c file:/opt/aws/amazon-cloudwatch-agent/etc/amazon-cloudwatch-agent.json -s

  # # Add Daily Security Update to crontab
  # cat > ~/mycron << 'EOF'
  # @daily yum -y update --security
  # EOF
  # crontab ~/mycron
  # rm ~/mycron
  # EOT
}

resource "aws_autoscaling_group" "autoscaling_group_proxy" {
  depends_on = [
    aws_elb.elb_proxy,
    aws_launch_configuration.autoscaling_group_config_proxy
  ]
  # NOTE: availability_zones is excluded as it Conflicts with vpc_zone_identifier
  # availability_zones = [
  #   var.region_az1_name,
  #   var.region_az2_name
  # ]
  vpc_zone_identifier = [
    aws_subnet.transit_dmz_subnet_A.id,
    aws_subnet.transit_dmz_subnet_B.id
  ]
  launch_configuration      = aws_launch_configuration.autoscaling_group_config_proxy.name
  max_size                  = var.proxy_auto_scale_max
  min_size                  = var.proxy_auto_scale_min
  load_balancers            = [aws_elb.elb_proxy.name]
  health_check_grace_period = 300
  health_check_type         = "ELB"
  tags = concat(
    [
      {
        "key"                 = "Name"
        "value"               = "ProxyServer"
        "propagate_at_launch" = true
      },
      {
        "key"                 = "Environment"
        "value"               = var.environment
        "propagate_at_launch" = true
      },
    ]
  )
}

#### FLOW LOG
resource "aws_cloudwatch_log_group" "transit_vpc_log_group" {
  name = "transit_vpc_log_group"
}

resource "aws_flow_log" "transit_vpc_flow_log" {
  iam_role_arn    = aws_iam_role.transit_vpc_flow_logs_service_role.arn
  log_destination = aws_cloudwatch_log_group.transit_vpc_log_group.arn # not sure about this
  traffic_type    = "ALL"
  vpc_id          = aws_vpc.transit_vpc.id
}

#### LOAD BALANCER 
resource "aws_elb" "elb_proxy" {
  depends_on = [
    aws_security_group.security_group_proxy_elb,
    aws_subnet.transit_dmz_subnet_A,
    aws_subnet.transit_dmz_subnet_B
  ]
  subnets = [
    aws_subnet.transit_dmz_subnet_A.id,
    aws_subnet.transit_dmz_subnet_B.id
  ]
  health_check {
    healthy_threshold   = 2
    unhealthy_threshold = 3
    timeout             = 5
    target              = "TCP:3128"
    interval            = 15
  }
  security_groups = [aws_security_group.security_group_proxy_elb.id]
  listener {
    instance_port     = 3128
    instance_protocol = "TCP"
    lb_port           = 80
    lb_protocol       = "TCP"
  }
  listener {
    instance_port     = 3128
    instance_protocol = "TCP"
    lb_port           = 443
    lb_protocol       = "TCP"
  }
  listener {
    instance_port     = 3128
    instance_protocol = "TCP"
    lb_port           = 3128
    lb_protocol       = "TCP"
  }

  access_logs {
    bucket        = var.logs_bucket
    bucket_prefix = "ElbAccessLogs"
    enabled       = true
    interval      = 60
  }

  tags = {
    Name        = "ProxyELB"
    Environment = var.environment
  }
}

#### IAM POLICY
resource "aws_iam_policy" "lambda_move_pub_keys_xsit_policy" {
  name = "LambdaMovePubKeysXsitPolicy"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "LambdaMovePubKeysS3Access"
        Action = [
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Effect   = "Allow"
        Resource = "arn:${var.region_partition}:s3:::${var.logs_bucket}/public-keys/*"
      }
    ]
  })
}

resource "aws_iam_policy" "transit_read_only_policy" {
  name        = "TransitReadOnlyPolicy"
  description = "Managed policy for TransitReadOnly permissions."
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid = "TransitReadOnlyEC2ELBReadAccess"
        Action = [
          "ec2:Describe*",
          "elasticloadbalancing:Describe*"
        ]
        Effect   = "Allow"
        Resource = "*"
      },
      {
        Sid = "TransitReadOnlyS3ReadAccess"
        Action = [
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ]
        Effect   = "Allow"
        Resource = "arn:${var.region_partition}:s3:::${var.logs_bucket}"
      },
      {
        Sid = "TransitReadOnlyS3WriteAccess"
        Action = [
          "s3:PutObject",
          "s3:GetObject",
          "s3:DeleteObject"
        ]
        Effect   = "Allow"
        Resource = "arn:${var.region_partition}:s3:::${var.logs_bucket}/public-keys/*"
      }
    ]
  })
}
