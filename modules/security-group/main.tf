resource "aws_security_group" "this" {
  name_prefix = var.name_prefix
  vpc_id      = var.vpc_id

  dynamic "ingress" {
    for_each = var.ingress_rules

    content {
      from_port   = ingress.value.from_port
      to_port     = ingress.value.to_port
      description = ingress.value.description
      protocol    = ingress.value.protocol
      cidr_blocks = ingress.value.cidr
    }
  }

  dynamic "egress" {
    for_each = var.egress_rules

    content {
      from_port         = egress.value.from_port
      to_port           = egress.value.to_port
      description       = egress.value.description
      protocol          = egress.value.protocol
      ipv6_cidr_blocks  = egress.value.ipv6_cidr_blocks
      cidr_blocks       = egress.value.cidr
    }
  }

  tags = var.core_tags
}