output "tenant_vpc" {
  value = aws_vpc.tenant_vpc.id
}

output "tenant_vpc_cidrblock" {
  value = aws_vpc.tenant_vpc.cidr_block
}

output "logs_bucket" {
  value = var.logs_bucket
}
