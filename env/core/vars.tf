variable "environment" {
  description = "The environment"
}

variable "project_name" {
  description = "The name of the project "
}

variable "vpc_id" {
  description = "The VPC id"
}

variable "public_subnet_ids" {
  description = "The public subnets to use"
}

variable "availability_zones_names" {
  description = "The azs to use"
}

variable "private_subnet_ids" {
  description = "The private subnets to use"
}

variable "core_tags" {
  type = map(string)
}

variable "ecs_container_name" { }

variable "kms_key_id_shared" { }

variable "certificate_arn" { }

variable "image_tag_mutability" { }

variable "image_scanning_configuration" { }

variable "cluster_version" { }