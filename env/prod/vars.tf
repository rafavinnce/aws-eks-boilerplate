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
  default = ""
}

variable "availability_zones_names" {
  description = "The azs to use"
}

variable "private_subnet_ids" {
  description = "The private subnets to use"
  default = ""
}

variable "core_tags" {
  type = map(string)
}

variable "ecs_container_name" { }

variable "kms_key_id_shared" { }

variable "certificate_arn" { }

variable "image_tag_mutability" { }

variable "image_scanning_configuration" { }

variable "local_aws_profile" { }

variable "region" { }
variable "cluster_version" { }

variable "lin_instance_type" {
  description = "Please enter the instance type to be used for the Linux worker nodes"
  type        = string
}
variable "lin_min_size" {
  description = "Please enter the minimal size for the Linux ASG"
  type        = string
}
variable "lin_max_size" {
  description = "Please enter the maximal size for the Linux ASG"
  type        = string
}
variable "lin_desired_size" {
  description = "Please enter the desired size for the Linux ASG"
  type        = string
}

variable "security_group_bastion" {
  type = string
  default = null
}

variable "sg_aditional" { }
variable "ec2_bastion_role_arn" { }
variable "encrypted" { }
