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

  ingress = [
    {
      description = "HTTP traffic from Transit"
      from_port   = 80
      to_port     = 80
      protocol    = "tcp"
      cidr_blocks = [var.transit_cidr]
    },
    {
      description = "HTTPS traffic from Transit"
      from_port   = 443
      to_port     = 443
      protocol    = "tcp"
      cidr_blocks = [var.transit_cidr]
    },
    {
      description = "Squid traffic from Transit"
      from_port   = 3128
      to_port     = 3128
      protocol    = "tcp"
      cidr_blocks = [var.transit_cidr]
    }
  ]

  egress = [
    {
      from_port        = 0
      to_port          = 0
      protocol         = "-1"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = ["::/0"]
    }
  ]

  tags = {
    Name        = "sg-web-proxy-ports-to-elb"
    Environment = var.environment
  }
}

resource "aws_security_group" "security_group_bastion" {
  description = "SG for Bastion Instance"
  vpc_id      = aws_vpc.transit_vpc.id

  ingress = [
    {
      description = "SSH connection traffic"
      from_port   = 22
      to_port     = 22
      protocol    = "tcp"
      cidr_blocks = [var.bastion_ssh_cidr]
    }
  ]

  egress = [
    {
      from_port        = 0
      to_port          = 0
      protocol         = "-1"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = ["::/0"]
    }
  ]

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

  ingress = [
    {
      description     = "Squid traffic"
      from_port       = 3128
      to_port         = 3128
      protocol        = "tcp"
      security_groups = [aws_security_group.security_group_proxy_elb.id]
    },
    {
      description     = "SSH connection traffic"
      from_port       = 22
      to_port         = 22
      protocol        = "tcp"
      security_groups = [aws_security_group.security_group_bastion.id]
    },
    {
      description = "NTP traffic"
      from_port   = 123
      to_port     = 123
      protocol    = "udp"
      cidr_blocks = ["10.0.0.0/16"]
    }
  ]

  egress = [
    {
      from_port        = 0
      to_port          = 0
      protocol         = "-1"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = ["::/0"]
    }
  ]

  tags = {
    Name        = "sg-web-proxy-ports-to-instances"
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
    Name = "Transit DMZ Subnet A"
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

  route = [
    {
      cidr_block = "10.0.1.0/24"
      gateway_id = aws_internet_gateway.example.id
    },
    {
      ipv6_cidr_block        = "::/0"
      egress_only_gateway_id = aws_egress_only_internet_gateway.example.id
    }
  ]

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
