//GLOBAL
environment                     = "prd"
region                          = "sa-east-1"
vpc_id                          = "vpc-01095b47e31dddb22"
public_subnet_ids               = ["subnet-0434bc5acf2b28c8a", "subnet-0dea2c91d63cdcc30"]
private_subnet_ids              =  ["subnet-08cd6709b0f6f8a91", "subnet-0489be1815252a915", "subnet-0a024ec1653a0a513"]
availability_zones_names        = ["sa-east-1a", "sa-east-1b", "sa-east-1c"]
project_name                    = "ops-data-discovery"
ecs_container_name              = "ops-data-discovery"
certificate_arn                 = "arn:aws:acm:sa-east-1:334901168872:certificate/e1489cb5-98b3-4668-b63e-ae33427764aa"
kms_key_id_shared               = "dded9c8a-a41b-4a28-9c64-1a3acfcdfb9e"
local_aws_profile               = "digio-onetrust"
cluster_version                 = "1.23"

//ECR
image_scanning_configuration     = true
image_tag_mutability             = "MUTABLE"

//TAGS
core_tags       = {
  owner         = "Arquitetura"
  ambiente      = "prod"
  workload      = "ops-data-discovery"
  cost-center   = "55210210"
  funcionamento = "24x7"
}

### Linux Nodegroup
lin_desired_size = "2"
lin_max_size = "2"
lin_min_size = "2"
lin_instance_type = "t3.medium"