variable "core_tags" { }
variable "vpc_id" { }
variable "environment" { }
variable "project_name" { }
variable "name_prefix" { }

variable "ingress_rules" {
  type = list(object({
    protocol = string
    from_port = number
    to_port = number
    description = string
    cidr = list(string)
  }))
  description = "Specify the protocol, port range, and CIDRs."
}

variable "egress_rules" {
  type = list(object({
    protocol = string
    from_port = number
    to_port = number
    description = string
    cidr = list(string)
    ipv6_cidr_blocks = list(string)
  }))
  description = "Specify the protocol, port range, and CIDRs."
}