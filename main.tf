module "tenant" {
  source = "./modules/tenant"
  tenant_vpc_name = var.tenant_vpc_name
  availability_zone_a = var.availability_zone_a
  availability_zone_b = var.availability_zone_b
  peer_vpc_id = var.peer_vpc_id
  peer_role_arn = var.peer_role_arn
  peer_vpc_account_id = var.peer_vpc_account_id



}

# module "iam" {
#   source = "./modules/iam"
# }

# module "payer" {
#   source = "./modules/payer"
#   billing_bucket = "payeraccount1"
# }