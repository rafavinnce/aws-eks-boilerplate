locals {
  bastion_user_data = <<-EOT
    #!/bin/bash
  curl -LO "https://storage.googleapis.com/kubernetes-release/release/$(curl -s https://storage.googleapis.com/kubernetes-release/release/stable.txt)/bin/linux/amd64/kubectl"
  chmod +x ./kubectl
  sudo mv ./kubectl /usr/local/bin/kubectl
  EOT
}

data "aws_caller_identity" "current" { }

provider "kubernetes" {
  host                   = module.eks_cluster.cluster_endpoint
  cluster_ca_certificate = base64decode(module.eks_cluster.cluster_certificate_authority_data)

  exec {
    api_version = "client.authentication.k8s.io/v1beta1"
    command     = "aws"
    # This requires the awscli to be installed locally where Terraform is executed
    args = ["--region", "sa-east-1", "eks", "get-token", "--cluster-name", module.eks_cluster.cluster_id]
  }
}

module "eks_cluster" {
  source                            = "../../modules/eks/eks-cluster"
  providers           = {
    aws = aws.digio-onetrust
  }
  cluster_name                    = "${var.environment}-${var.project_name}"
  cluster_version                 = var.cluster_version
  cluster_endpoint_private_access = true
  cluster_endpoint_public_access  = false
  cluster_enabled_log_types       = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  cluster_addons = {
    coredns = {
      addon_version = "v1.8.7-eksbuild.3" // eks 1.22(v1.8.7-eksbuild.1) | eks 1.14(v1.8.7-eksbuild.3) | 1.23 (v1.8.7-eksbuild.3)
      resolve_conflicts = "OVERWRITE"
    }
    kube-proxy = {
      addon_version = "v1.23.8-eksbuild.2" //eks 1.23(v1.23.8-eksbuild.2) | 1.24(v1.24.9-eksbuild.1)
      resolve_conflicts = "OVERWRITE"
    }
    vpc-cni = {
      addon_version = "v1.12.1-eksbuild.2"
      resolve_conflicts = "OVERWRITE"
    }
  }

  # Encryption key
  create_kms_key = true
  cluster_encryption_config = [{
    resources = ["secrets"]
  }]
  kms_key_deletion_window_in_days = 7
  enable_kms_key_rotation         = true

  vpc_id                   = var.vpc_id
  subnet_ids               = var.private_subnet_ids
  control_plane_subnet_ids = var.private_subnet_ids

  # Extend cluster security group rules
  cluster_security_group_additional_rules = {
    ingress_bastion = {
      description       = "Allow access from Bastion Host"
      type              = "ingress"
      from_port         = 443
      to_port           = 443
      protocol          = "tcp"
      source_security_group_id = var.sg_aditional
    }
    egress_nodes_ephemeral_ports_tcp = {
      description                = "To node 1025-65535"
      protocol                   = "tcp"
      from_port                  = 1025
      to_port                    = 65535
      type                       = "egress"
      source_node_security_group = true
    }
    egress_nodes_job_manager_tcp = {
      description                = "Allow Scan Job Manager"
      protocol                   = "tcp"
      from_port                  = 8081
      to_port                    = 8081
      type                       = "egress"
      cidr_blocks                = ["0.0.0.0/0"]
      ipv6_cidr_blocks           = ["::/0"]
    }
    egress_nodes_https_tcp = {
      description                = "Allow Https"
      protocol                   = "tcp"
      from_port                  = 443
      to_port                    = 443
      type                       = "egress"
      cidr_blocks                = ["0.0.0.0/0"]
      ipv6_cidr_blocks           = ["::/0"]
    }
  }

  # Extend node-to-node security group rules
  node_security_group_additional_rules = {
    ingress_self_all = {
      description = "Node to node all ports/protocols"
      protocol    = "-1"
      from_port   = 0
      to_port     = 0
      type        = "ingress"
      self        = true
    }
    egress_all = {
      description      = "Node all egress"
      protocol         = "-1"
      from_port        = 0
      to_port          = 0
      type             = "egress"
      cidr_blocks      = ["0.0.0.0/0"]
      ipv6_cidr_blocks = ["::/0"]
    }
    ## Enable access from bastion host to Nodes
    ingress_bastion = {
      description       = "Allow access from Bastion Host"
      type              = "ingress"
      from_port         = 443
      to_port           = 443
      protocol          = "tcp"
      source_security_group_id = var.sg_aditional
    }
    ## Enable RDP access from bastion host to Nodes
    ingress_bastion_win = {
      description       = "Allow access from Bastion Host via RDP"
      type              = "ingress"
      from_port         = 3389
      to_port           = 3389
      protocol          = "tcp"
      source_security_group_id = var.sg_aditional
    }

    ingress_fargate = {
      description       = "Allow access from Fargate"
      type              = "ingress"
      from_port         = 0
      to_port           = 0
      protocol          = "tcp"
      source_security_group_id = "sg-0cd9e75cfe15ccf7b"
    }
  }

  # Self Managed Node Group(s)
  ### Allow SSM access for Nodes
#  self_managed_node_group_defaults = {
#    vpc_security_group_ids                 = [module.security_group_aditional.id]
#    iam_role_additional_policies           = ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]
#  }
#  self_managed_node_group_defaults = {
#    vpc_security_group_ids       = [module.security_group_aditional.id]
#    iam_role_additional_policies = ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]
#  }

  #  cluster_name        = module.eks_cluster.cluster_id
  #  cluster_version     = module.eks_cluster.cluster_version
  #  cluster_endpoint    = module.eks_cluster.cluster_endpoint
  #  cluster_auth_base64 = module.eks_cluster.cluster_certificate_authority_data

#  self_managed_node_groups = {
#    linux = {
#      platform = "linux"
#      name = "linux"
#      public_ip    = false
#      instance_type = var.lin_instance_type
#      key_name = module.keypair.key_name
#      desired_size = var.lin_desired_size
#      max_size = var.lin_max_size
#      min_size = var.lin_min_size
#      ami_id = data.aws_ami.lin_ami.id
#      tags = merge(var.core_tags,
#        tomap(
#          {"funcao" = "eks-node-group"}
#        )
#      )
#    }
#  }

#  self_managed_node_groups = {
#    spot = {
#      instance_type = "m5.large"
#      instance_market_options = {
#        market_type = "spot"
#      }
#
#      pre_bootstrap_user_data = <<-EOT
#      echo "foo"
#      export FOO=bar
#      EOT
#
#      bootstrap_extra_args = "--kubelet-extra-args '--node-labels=node.kubernetes.io/lifecycle=spot'"
#
#      post_bootstrap_user_data = <<-EOT
#      cd /tmp
#      sudo yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm
#      sudo systemctl enable amazon-ssm-agent
#      sudo systemctl start amazon-ssm-agent
#      EOT
#    }
#  }

  # EKS Managed Node Group(s)
#  eks_managed_node_group_defaults = {
#    ami_type       = "AL2_x86_64"
#    instance_types = ["c5.2xlarge"]
#
#    attach_cluster_primary_security_group = true
#    vpc_security_group_ids                = [module.security_group_aditional.id]
#  }

#  eks_managed_node_groups = {
#    eks-green = {
#      min_size     = 2
#      max_size     = 2
#      desired_size = 2
#
#      instance_types = ["c5.2xlarge"]
#      capacity_type  = "SPOT"
#      labels = {
#        Environment = var.environment
#        Workload    = var.project_name
#      }
#
#      taints = {
#        dedicated = {
#          key    = "dedicated"
#          value  = "gpuGroup"
#          effect = "NO_SCHEDULE"
#        }
#      }
#
#      update_config = {
#        max_unavailable_percentage = 50 # or set `max_unavailable`
#      }
#
#      tags = merge(var.core_tags,
#        tomap(
#          {"funcao" = "eks-cluster"}
#        )
#      )
#    }
#  }

  # Fargate Profile(s)
  fargate_profiles = {
    default = {
      name = "default"
      selectors = [
        {
          namespace = "kube-system"
          labels = {
            k8s-app = "kube-dns"
          }
        },
        {
          namespace = "default"
        },
        {
          namespace = "efs-provisioner"
        },
        {
          namespace = "onetrust"
        }
      ]

      tags = merge(var.core_tags,
        tomap(
          {"funcao" = "ecr"}
        )
      )

      timeouts = {
        create = "20m"
        delete = "20m"
      }
    }
  }

    # aws-auth configmap
#    manage_aws_auth_configmap = true
#   create_aws_auth_configmap = true

#  aws_auth_node_iam_role_arns_non_windows = [
#    module.eks_managed_node_group.iam_role_arn,
#    module.self_managed_node_group.iam_role_arn,
#  ]

  aws_auth_fargate_profile_pod_execution_role_arns = [
    module.fargate_profile.fargate_profile_pod_execution_role_arn
  ]

  aws_auth_roles = [
    {
      rolearn  = "arn:aws:iam::351276562033:role/Infraestrutura"
      username = "infraestrutura"
      groups   = ["system:masters"]
    },
    {
      rolearn  = "arn:aws:iam::334901168872:role/C2G-N3"
      username = "nextiosn3"
      groups   = ["system:masters"]
    },
    {
      rolearn  = "arn:aws:iam::334901168872:role/C2G-N2"
      username = "nextiosn2"
      groups   = ["system:masters"]
    },
    {
      rolearn  = "arn:aws:iam::334901168872:role/C2G-N1"
      username = "nextion1"
      groups   = ["system:masters"]
    },
    {
      rolearn  = "arn:aws:iam::334901168872:role/C2G-DBA"
      username = "nextiosdba"
      groups   = ["system:masters"]
    },
    {
      rolearn  = var.ec2_bastion_role_arn
      username = "bastion"
      groups   = ["system:masters"]
    },
    {
      rolearn  = module.eks_cluster.cluster_iam_role_arn
      username = "bastion"
      groups   = ["system:masters"]
    },
    {
      rolearn  = "arn:aws:iam::785212834098:role/AWSReservedSSO_UAT_NPRD-C2G-N3_SSO_1b6debba86a212e5"
      username = "SSO_UAT_NPRD-C2G-N3_SSO_1b6debba86a212e5"
      groups   = ["system:masters"]
    },
    {
      rolearn  = "arn:aws:iam::785212834098:role/AWSReservedSSO_UAT_NPRD-Infraestrutura_SSO_6d4923472cfe9c12"
      username = "SSO_UAT_NPRD-Infraestrutura_SSO_6d4923472cfe9c12"
      groups   = ["system:masters"]
    },
    {
      rolearn  = "arn:aws:iam::785212834098:role/AWSReservedSSO_UAT_Arquitetura-Sustentacao_SSO_baa4c9a37cd15075"
      username = "SSO_UAT_Arquitetura-Sustentacao_SSO_baa4c9a37cd15075"
      groups   = ["system:masters"]
    },
    {
      rolearn  = "arn:aws:iam::978388149693:role/AWSReservedSSO_PRD_C2G-N3_SSO_1a5bc3e3b574c695"
      username = "AWSReservedSSO_PRD_C2G-N3_SSO_1a5bc3e3b574c695"
      groups   = ["system:masters"]
    },
    {
      rolearn  = "arn:aws:iam::978388149693:role/AWSReservedSSO_PRD_Infraestrutura_SSO_c0c278718a525307"
      username = "AWSReservedSSO_PRD_Infraestrutura_SSO_c0c278718a525307"
      groups   = ["system:masters"]
    },
  ]

  aws_auth_users = [
    {
      userarn  = "arn:aws:iam::978388149693:user/user_onetrust"
      username = "user_onetrust"
      groups   = ["system:masters"]
    },
  ]

  aws_auth_accounts = [
    "978388149693",
    "584539243974",
    "785212834098",
    "334901168872",
  ]

  tags = merge(var.core_tags,
    tomap(
      {"funcao" = "eks"}
    )
  )
}

module "fargate_profile" {
  source = "../../modules/eks/eks-cluster/modules/fargate-profile"

  name         = "${var.project_name}-sp-fargate-pf"
  cluster_name = module.eks_cluster.cluster_id

  subnet_ids = var.private_subnet_ids
  selectors = [{
    namespace = "kube-system",
    labels = {
      k8s-app = "kube-dns"
    }
  }]

  tags = merge(var.core_tags,
    tomap(
      {"funcao" = "fargate-profile"}
    )
  )
}

#module "eks_managed_node_group" {
#  source = "../../modules/eks/eks-cluster/modules/eks-managed-node-group"

#
#  name            = "separate-eks-mng"
#  cluster_name    = module.eks_cluster.cluster_id
#  cluster_version = module.eks_cluster.cluster_version
#
#  vpc_id                            = var.vpc_id
#  subnet_ids                        = var.private_subnet_ids
#  cluster_primary_security_group_id = module.eks_cluster.cluster_primary_security_group_id
#  vpc_security_group_ids = [
#    module.eks_cluster.cluster_security_group_id,
#  ]
#
#  tags = merge(var.core_tags,
#    tomap(
#      {"funcao" = "eks-managed-node-group"}
#    )
#  )
#}

#module "security_group_aditional" {
#  source = "../../modules/security-group"
#

#
#  name_prefix     = "${var.environment}-${var.project_name}-aditional"
#  vpc_id          = var.vpc_id
#  environment     = var.environment
#  project_name    = var.project_name
#  core_tags       = merge(var.core_tags,
#    tomap(
#      {"funcao" = "sg-aditional"}
#    )
#  )
#
#  ingress_rules = [
#
#  ]
#}

#module "self_managed_node_group" {
#  source = "../../modules/eks/eks-cluster/modules/self-managed-node-group"

#
#  name                = "${var.project_name}-sp-self-mng"
#  cluster_name        = module.eks_cluster.cluster_id
#  cluster_version     = module.eks_cluster.cluster_version
#  cluster_endauthpoint    = module.eks_cluster.cluster_endpoint
#  cluster_auth_base64 = module.eks_cluster.cluster_certificate_authority_data
#  platform            = "linux"
#  key_name            = module.keypair.key_name
#
#
#  instance_type = "m5.large"
#
#  vpc_id     = var.vpc_id
#  subnet_ids = var.private_subnet_ids
#  vpc_security_group_ids = [
#    module.eks_cluster.cluster_primary_security_group_id,
#    module.eks_cluster.cluster_security_group_id,
#  ]
#
#  use_default_tags = true
#
#  tags = merge(var.core_tags,
#    tomap(
#      {"funcao" = "self-managed-node-group"}
#    )
#  )
#}
#

# VPC Endpoints for private EKS cluster
# https://docs.aws.amazon.com/eks/latest/userguide/private-clusters.html#vpc-endpoints-private-clusters

#### Route Tables for S3 Gateway
data "aws_route_table" "private-a" {
  subnet_id = var.private_subnet_ids[0]
}
data "aws_route_table" "private-b" {
  subnet_id = var.private_subnet_ids[1]
}
data "aws_route_table" "private-c" {
  subnet_id = var.private_subnet_ids[2]
}

resource "aws_vpc_endpoint" "vpce_s3_gw" {
  policy = jsonencode(
    {
      Statement = [
        {
          Action    = "*"
          Effect    = "Allow"
          Principal = "*"
          Resource  = "*"
        },
      ]
      Version = "2008-10-17"
    }
  )
  route_table_ids = [
    data.aws_route_table.private-a.id,
    data.aws_route_table.private-b.id,
    data.aws_route_table.private-c.id
  ]
  service_name       = format("com.amazonaws.${var.region}.s3")
  vpc_endpoint_type  = "Gateway"
  vpc_id = var.vpc_id
  tags = merge(var.core_tags,
    tomap(
      {"funcao" = "aws_vpc_endpoint-vpce_s3_gw"}
    )
  )
}
resource "aws_vpc_endpoint" "vpce_ec2" {
  policy = jsonencode(
    {
      Statement = [
        {
          Action    = "*"
          Effect    = "Allow"
          Principal = "*"
          Resource  = "*"
        },
      ]
    }
  )
  private_dns_enabled = true

  security_group_ids = [module.eks_cluster.node_security_group_id,module.eks_cluster.cluster_security_group_id]
  service_name = format("com.amazonaws.${var.region}.ec2")
  subnet_ids = var.private_subnet_ids
  vpc_endpoint_type = "Interface"
  vpc_id = var.vpc_id
  tags = merge(var.core_tags,
    tomap(
      {"funcao" = "aws_vpc_endpoint-vpce_ec2"}
    )
  )
}
resource "aws_vpc_endpoint" "vpce_logs" {
  policy = jsonencode(
    {
      Statement = [
        {
          Action    = "*"
          Effect    = "Allow"
          Principal = "*"
          Resource  = "*"
        },
      ]
    }
  )
  private_dns_enabled = true
  security_group_ids = [module.eks_cluster.node_security_group_id,module.eks_cluster.cluster_security_group_id]
  service_name = format("com.amazonaws.${var.region}.logs")
  subnet_ids = var.private_subnet_ids
  vpc_endpoint_type = "Interface"
  vpc_id = var.vpc_id
  tags = merge(var.core_tags,
    tomap(
      {"funcao" = "aws_vpc_endpoint-vpce_logs"}
    )
  )
}
resource "aws_vpc_endpoint" "vpce_ecrapi" {
  policy = jsonencode(
    {
      Statement = [
        {
          Action    = "*"
          Effect    = "Allow"
          Principal = "*"
          Resource  = "*"
        },
      ]
    }
  )
  private_dns_enabled = true
  security_group_ids = [module.eks_cluster.node_security_group_id,module.eks_cluster.cluster_security_group_id]
  service_name = format("com.amazonaws.${var.region}.ecr.api")
  subnet_ids = var.private_subnet_ids
  vpc_endpoint_type = "Interface"
  vpc_id = var.vpc_id
  tags = merge(var.core_tags,
    tomap(
      {"funcao" = "aws_vpc_endpoint-vpce_ecrapi"}
    )
  )
}
resource "aws_vpc_endpoint" "vpce_autoscaling" {
  policy = jsonencode(
    {
      Statement = [
        {
          Action    = "*"
          Effect    = "Allow"
          Principal = "*"
          Resource  = "*"
        },
      ]
    }
  )
  private_dns_enabled = true
  security_group_ids = [module.eks_cluster.node_security_group_id,module.eks_cluster.cluster_security_group_id]
  service_name = format("com.amazonaws.${var.region}.autoscaling")
  subnet_ids = var.private_subnet_ids
  vpc_endpoint_type = "Interface"
  vpc_id = var.vpc_id
  tags = merge(var.core_tags,
    tomap(
      {"funcao" = "aws_vpc_endpoint-vpce_autoscaling"}
    )
  )
}

resource "aws_vpc_endpoint" "vpce_sts" {
  policy = jsonencode(
    {
      Statement = [
        {
          Action    = "*"
          Effect    = "Allow"
          Principal = "*"
          Resource  = "*"
        },
      ]
    }
  )
  private_dns_enabled = true
  security_group_ids = [module.eks_cluster.node_security_group_id,module.eks_cluster.cluster_security_group_id]
  service_name = format("com.amazonaws.${var.region}.sts")
  subnet_ids = var.private_subnet_ids
  vpc_endpoint_type = "Interface"
  vpc_id = var.vpc_id
  tags = merge(var.core_tags,
    tomap(
      {"funcao" = "aws_vpc_endpoint-vpce_sts"}
    )
  )
}
resource "aws_vpc_endpoint" "vpce_elb" {
  policy = jsonencode(
    {
      Statement = [
        {
          Action    = "*"
          Effect    = "Allow"
          Principal = "*"
          Resource  = "*"
        },
      ]
    }
  )
  private_dns_enabled = true
  security_group_ids = [module.eks_cluster.node_security_group_id,module.eks_cluster.cluster_security_group_id]
  service_name = format("com.amazonaws.${var.region}.elasticloadbalancing")
  subnet_ids = var.private_subnet_ids
  vpc_endpoint_type = "Interface"
  vpc_id = var.vpc_id
  tags = merge(var.core_tags,
    tomap(
      {"funcao" = "aws_vpc_endpoint-vpce_elb"}
    )
  )
}
resource "aws_vpc_endpoint" "vpce_ecrdkr" {
  policy = jsonencode(
    {
      Statement = [
        {
          Action    = "*"
          Effect    = "Allow"
          Principal = "*"
          Resource  = "*"
        },
      ]
    }
  )
  private_dns_enabled = true
  security_group_ids = [module.eks_cluster.node_security_group_id,module.eks_cluster.cluster_security_group_id]
  service_name = format("com.amazonaws.${var.region}.ecr.dkr")
  subnet_ids = var.private_subnet_ids
  vpc_endpoint_type = "Interface"
  vpc_id = var.vpc_id
  tags = merge(var.core_tags,
    tomap(
      {"funcao" = "aws_vpc_endpoint-vpce_ecrdkr"}
    )
  )
}
### SSM Access
resource "aws_vpc_endpoint" "vpce_ec2messages" {
  policy = jsonencode(
    {
      Statement = [
        {
          Action    = "*"
          Effect    = "Allow"
          Principal = "*"
          Resource  = "*"
        },
      ]
    }
  )
  private_dns_enabled = true
  security_group_ids = [module.eks_cluster.node_security_group_id,module.eks_cluster.cluster_security_group_id]
  service_name = format("com.amazonaws.${var.region}.ec2messages")
  subnet_ids = var.private_subnet_ids
  vpc_endpoint_type = "Interface"
  vpc_id = var.vpc_id
  tags = merge(var.core_tags,
    tomap(
      {"funcao" = "aws_vpc_endpoint-vpce_ec2messages"}
    )
  )
}

resource "aws_vpc_endpoint" "vpce_ssm" {
  policy = jsonencode(
    {
      Statement = [
        {
          Action    = "*"
          Effect    = "Allow"
          Principal = "*"
          Resource  = "*"
        },
      ]
    }
  )
  private_dns_enabled = true
  security_group_ids = [module.eks_cluster.node_security_group_id,module.eks_cluster.cluster_security_group_id]
  service_name = format("com.amazonaws.${var.region}.ssm")
  subnet_ids = var.private_subnet_ids
  vpc_endpoint_type = "Interface"
  vpc_id = var.vpc_id

  tags = merge(var.core_tags,
    tomap(
      {"funcao" = "aws_vpc_endpoint-vpce_ssm"}
    )
  )
}

resource "aws_vpc_endpoint" "vpce_ssmmessages" {
  policy = jsonencode(
    {
      Statement = [
        {
          Action    = "*"
          Effect    = "Allow"
          Principal = "*"
          Resource  = "*"
        },
      ]
    }
  )
  private_dns_enabled = true
  security_group_ids = [module.eks_cluster.node_security_group_id,module.eks_cluster.cluster_security_group_id]
  service_name = format("com.amazonaws.${var.region}.ssmmessages")
  subnet_ids = var.private_subnet_ids
  vpc_endpoint_type = "Interface"
  vpc_id = var.vpc_id

  tags = merge(var.core_tags,
    tomap(
      {"funcao" = "aws_vpc_endpoint-vpce_ssmmessages"}
    )
  )
}

# Bastion Host
data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn-ami-hvm-*-x86_64-gp2"]
  }
}

#module "ec2_bastion" {
#  source = "../../modules/ec2"
#
#  name                        = "${var.environment}-${var.project_name}-bastion"
#
#  ami                         = data.aws_ami.amazon_linux.id
#  instance_type               = "t3.large"
#  availability_zone           = var.availability_zones_names[0]
#  subnet_id                   = var.private_subnet_ids[0]
#  vpc_security_group_ids      = [module.security_group_aditional.id]
#
#  user_data_base64            = base64encode(local.bastion_user_data)
#  user_data_replace_on_change = true
#
#  enable_volume_tags = false
#  root_block_device = [
#    {
#      encrypted   = true
#      volume_type = "gp3"
#      throughput  = 200
#      volume_size = 50
#      tags = {
#        Name = "bastion-root-block"
#      }
#    },
#  ]
#
#  ebs_block_device = [
#    {
#      device_name = "/dev/sdf"
#      volume_type = "gp3"
#      volume_size = 5
#      throughput  = 200
#      encrypted   = true
#      kms_key_id  = aws_kms_key.this.arn
#    }
#  ]
#
#  tags = merge(var.core_tags,
#    tomap(
#      {"funcao" = "eks_ec2_bastion"}
#    )
#  )
#}
#
#resource "aws_kms_key" "this" {
#  enable_key_rotation = "true"
#}

#### Nodegroups - Images

data "aws_ami" "lin_ami" {
  most_recent = true
  owners = ["amazon"]
  filter {
    name = "name"
    values = ["amazon-eks-node-${var.cluster_version}-*"]
  }
}

#data "aws_ami" "win_ami" {
#  most_recent = true
#  owners = ["amazon"]
#  filter {
#    name = "name"
#    values = ["Windows_Server-2022-*"]
#  }
#}

#module "keypair" {
#  source  = "mitchellh/dynamic-keys/aws"
#  version = "2.0.0"
#  path    = "keys/${var.environment}"
#  name    = "kp-${var.environment}-${var.project_name}"
#}
#
#

#module "ec2_windows" {
#  source = "../../modules/ec2"
#
#  name                        = "${var.environment}-${var.project_name}-win-test"
#
#  ami                         = data.aws_ami.win_ami.id
#  instance_type               = "c5.large"
#  availability_zone           = var.availability_zones_names[0]
#  subnet_id                   = var.private_subnet_ids[0]
#  vpc_security_group_ids      = [module.security_group_aditional.id]
#
#  user_data                   = data.template_file.windows-userdata.rendered
#  user_data_replace_on_change = true
#
#  enable_volume_tags = false
#  root_block_device = [
#    {
#      encrypted   = true
#      volume_type = "gp3"
#      throughput  = 200
#      volume_size = 50
#      tags = {
#        Name = "windows-root-block"
#      }
#    },
#  ]
#
#  ebs_block_device = [
#    {
#      device_name = "/dev/sdf"
#      volume_type = "gp3"
#      volume_size = 5
#      throughput  = 200
#      encrypted   = true
#      kms_key_id  = aws_kms_key.this.arn
#    }
#  ]
#
#  tags = merge(var.core_tags,
#    tomap(
#      {"funcao" = "ec2_windiws"}
#    )
#  )
#}
#
#data "template_file" "windows-userdata" {
#  template = <<EOF
#<powershell>
## Rename Machine
#Rename-Computer -NewName "${var.environment}-${var.project_name}" -Force;
## Install IIS
#Install-WindowsFeature -name Web-Server -IncludeManagementTools;
## Restart machine
#shutdown -r -t 10;
#</powershell>
#EOF
#}

module "efs" {
  source    = "../../modules/efs"

  providers           = {
    aws = aws.digio-onetrust
  }

  name                       = "fs-${var.environment}-${var.project_name}"
  mount_target_subnet        = var.private_subnet_ids[0]
  core_tags                  = var.core_tags
  encrypted                  = var.encrypted
}

#module "metrics-server" {
#  source    = "../../modules/metrics-server"
#
#  providers           = {
#    aws = aws.digio-onetrust
#  }
#
#  helm_chart_name                         = "metrics-server"
#  helm_chart_version                      = "6.0.0"
#  helm_cleanup_on_fail                    = "false"
#  helm_create_namespace                   = "false"
#  helm_dependency_update                  = "false"
#  helm_description                        = "Metrics Server Release"
#  helm_devel                              = "false"
#  helm_disable_openapi_validation         = "false"
#  helm_disable_webhooks                   = "false"
#  helm_force_update                       = "false"
#  helm_keyring                            = "~/.gnupg/pubring.gpg"
#  helm_lint                               = "false"
#  helm_package_verify                     = "false"
#  helm_recreate_pods                      = "false"
#  helm_release_name                       = "metrics-server"
#  helm_release_max_history                = 0
#  helm_repo_url                           = "https://charts.bitnami.com/bitnami"
#  helm_repo_password                      = ""
#  helm_timeout                            = 300
#  namespace                               = "onetrust"
#}
