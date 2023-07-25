#data "aws_caller_identity" "current" { }
#
#resource "random_password" "master" {
#  length = 10
#}
#
##module "efs" {
##  source    = "../../modules/efs"
##  providers = {
##    aws = aws.digio-onetrust
##  }
##
##  name                       = "fs-${var.environment}-${var.project_name}"
##  mount_target_subnet        = var.private_subnet_ids[0]
##  core_tags                  = var.core_tags
##}
#

#module "data-ecr" {
#  providers = {
#    aws = aws.infra
#  }
#  source                        = "../../modules/data_ecr"
#  environment                   = var.environment
#  name                          = "infrashared-${var.project_name}"
#  project_name                  = var.project_name
#}

##module "main-secret" {
##  source              = "../../modules/secrets"
##  providers           = {
##    aws = aws.digio-onetrust
##  }
##
##  secret_keys         = {
##    VAR1   = "111"
##    VAR2   = "222"
##  }
##
##  name                = "${var.environment}-${var.project_name}-secrets"
##  environment         = var.environment
##  project_name        = var.project_name
##  account_id          = data.aws_caller_identity.current.account_id
##  core_tags           = var.core_tags
##}
#
#provider "kubernetes" {
#  host                   = module.eks_cluster.cluster_endpoint
#  cluster_ca_certificate = base64decode(module.eks_cluster.cluster_certificate_authority_data)
#
#  exec {
#    api_version = "client.authentication.k8s.io/v1beta1"
#    command     = "aws"
#    # This requires the awscli to be installed locally where Terraform is executed
#    args = ["--region", "sa-east-1", "--profile", var.local_aws_profile, "eks", "get-token", "--cluster-name", module.eks_cluster.cluster_id]
#  }
#}
#
#module "eks_cluster" {
#  source                            = "../../modules/eks/eks-cluster"
#  providers           = {
#    aws = aws.digio-onetrust
#  }
#  cluster_name                    = "${var.environment}-${var.project_name}"
#  cluster_endpoint_private_access = true
#  cluster_endpoint_public_access  = true
#
#  cluster_addons = {
#    coredns = {
#      resolve_conflicts = "OVERWRITE"
#    }
#    kube-proxy = {}
#    vpc-cni = {
#      resolve_conflicts = "OVERWRITE"
#    }
#  }
#
#  # Encryption key
#  create_kms_key = true
#  cluster_encryption_config = [{
#    resources = ["secrets"]
#  }]
#  kms_key_deletion_window_in_days = 7
#  enable_kms_key_rotation         = true
#
#  vpc_id                   = var.vpc_id
#  subnet_ids               = var.private_subnet_ids
#  control_plane_subnet_ids = var.private_subnet_ids
#
#  # Extend cluster security group rules
#  cluster_security_group_additional_rules = {
#    egress_nodes_ephemeral_ports_tcp = {
#      description                = "To node 1025-65535"
#      protocol                   = "tcp"
#      from_port                  = 1025
#      to_port                    = 65535
#      type                       = "egress"
#      source_node_security_group = true
#    }
#  }
#
#  # Extend node-to-node security group rules
#  node_security_group_ntp_ipv4_cidr_block = ["169.254.169.123/32"]
#  node_security_group_additional_rules = {
#    ingress_self_all = {
#      description = "Node to node all ports/protocols"
#      protocol    = "-1"
#      from_port   = 0
#      to_port     = 0
#      type        = "ingress"
#      self        = true
#    }
#    egress_all = {
#      description      = "Node all egress"
#      protocol         = "-1"
#      from_port        = 0
#      to_port          = 0
#      type             = "egress"
#      cidr_blocks      = ["0.0.0.0/0"]
#      ipv6_cidr_blocks = ["::/0"]
#    }
#  }
#
#  # Self Managed Node Group(s)
##  self_managed_node_group_defaults = {
##    vpc_security_group_ids       = [module.security_group_aditional.id]
##    iam_role_additional_policies = ["arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"]
##  }
#
##  self_managed_node_groups = {
##    spot = {
##      instance_type = "m5.large"
##      instance_market_options = {
##        market_type = "spot"
##      }
##
##      pre_bootstrap_user_data = <<-EOT
##      echo "foo"
##      export FOO=bar
##      EOT
##
##      bootstrap_extra_args = "--kubelet-extra-args '--node-labels=node.kubernetes.io/lifecycle=spot'"
##
##      post_bootstrap_user_data = <<-EOT
##      cd /tmp
##      sudo yum install -y https://s3.amazonaws.com/ec2-downloads-windows/SSMAgent/latest/linux_amd64/amazon-ssm-agent.rpm
##      sudo systemctl enable amazon-ssm-agent
##      sudo systemctl start amazon-ssm-agent
##      EOT
##    }
##  }
##
#  # EKS Managed Node Group(s)
##  eks_managed_node_group_defaults = {
##    ami_type       = "AL2_x86_64"
##    instance_types = ["c5.2xlarge"]
##
##    attach_cluster_primary_security_group = true
##    vpc_security_group_ids                = [module.security_group_aditional.id]
##  }
#
##  eks_managed_node_groups = {
##    eks-green = {
##      min_size     = 2
##      max_size     = 2
##      desired_size = 2
##
##      instance_types = ["c5.2xlarge"]
##      capacity_type  = "SPOT"
##      labels = {
##        Environment = var.environment
##        Workload    = var.project_name
##      }
##
##      taints = {
##        dedicated = {
##          key    = "dedicated"
##          value  = "gpuGroup"
##          effect = "NO_SCHEDULE"
##        }
##      }
##
##      update_config = {
##        max_unavailable_percentage = 50 # or set `max_unavailable`
##      }
##
##      tags = merge(var.core_tags,
##        tomap(
##          {"funcao" = "eks-cluster"}
##        )
##      )
##    }
##  }
#
#  # Fargate Profile(s)
#  fargate_profiles = {
#    default = {
#      name = "default"
#      selectors = [
#        {
#          namespace = "kube-system"
#          labels = {
#            k8s-app = "kube-dns"
#          }
#        },
#        {
#          namespace = "default"
#        }
#      ]
#
#      tags = merge(var.core_tags,
#        tomap(
#          {"funcao" = "ecr"}
#        )
#      )
#
#      timeouts = {
#        create = "20m"
#        delete = "20m"
#      }
#    }
#  }
#
#  # aws-auth configmap
#  manage_aws_auth_configmap = true
#  create_aws_auth_configmap = true
#
#  #aws_auth_node_iam_role_arns_non_windows = [
#  #  module.eks_managed_node_group.iam_role_arn,
##    module.self_managed_node_group.iam_role_arn,
#  #]
#  aws_auth_fargate_profile_pod_execution_role_arns = [
#    module.fargate_profile.fargate_profile_pod_execution_role_arn
#  ]
#
#  aws_auth_roles = [
#    {
#      rolearn  = "arn:aws:iam::351276562033:role/Infraestrutura"
#      username = "infraestrutura"
#      groups   = ["system:masters"]
#    },
#    {
#      rolearn  = "arn:aws:iam::334901168872:role/C2G-N3"
#      username = "nextiosn3"
#      groups   = ["system:masters"]
#    },
#    {
#      rolearn  = "arn:aws:iam::334901168872:role/C2G-N2"
#      username = "nextiosn2"
#      groups   = ["system:masters"]
#    },
#    {
#      rolearn  = "arn:aws:iam::334901168872:role/C2G-N1"
#      username = "nextion1"
#      groups   = ["system:masters"]
#    },
#    {
#      rolearn  = "arn:aws:iam::334901168872:role/C2G-DBA"
#      username = "nextiosdba"
#      groups   = ["system:masters"]
#    },
#  ]
#
#  aws_auth_users = [
##    {
##      userarn  = "arn:aws:iam::785212834098:user/user1"
##      username = "user1"
##      groups   = ["system:masters"]
##    },
#  ]
#
#  aws_auth_accounts = [
##    "584539243974",
##    "785212834098",
##    "334901168872",
#  ]
#
#  tags = merge(var.core_tags,
#    tomap(
#      {"funcao" = "eks"}
#    )
#  )
#}
#
#module "fargate_profile" {
#  source = "../../modules/eks/eks-cluster/modules/fargate-profile"
#  providers           = {
#    aws = aws.digio-onetrust
#  }
#
#  name         = "${var.project_name}-sp-fargate-pf"
#  cluster_name = module.eks_cluster.cluster_id
#
#  subnet_ids = var.private_subnet_ids
#  selectors = [{
#    namespace = "kube-system"
#  }]
#
#  tags = merge(var.core_tags,
#    tomap(
#      {"funcao" = "fargate-profile"}
#    )
#  )
#}
#
##module "eks_managed_node_group" {
##  source = "../../modules/eks/eks-cluster/modules/eks-managed-node-group"
##  providers           = {
##    aws = aws.digio-onetrust
##  }
##
##  name            = "separate-eks-mng"
##  cluster_name    = module.eks_cluster.cluster_id
##  cluster_version = module.eks_cluster.cluster_version
##
##  vpc_id                            = var.vpc_id
##  subnet_ids                        = var.private_subnet_ids
##  cluster_primary_security_group_id = module.eks_cluster.cluster_primary_security_group_id
##  vpc_security_group_ids = [
##    module.eks_cluster.cluster_security_group_id,
##  ]
##
##  tags = merge(var.core_tags,
##    tomap(
##      {"funcao" = "eks-managed-node-group"}
##    )
##  )
##}
#
#module "security_group_aditional" {
#  source = "../../modules/security-group"
#
#  providers           = {
#    aws = aws.digio-onetrust
#  }
#
#  name_prefix     = "${var.environment}-${var.project_name}-additional"
#  vpc_id          = var.vpc_id
#  environment     = var.environment
#  project_name    = var.project_name
#  core_tags       = merge(var.core_tags,
#    tomap(
#      {"funcao" = "sg-aditional"}
#    )
#  )
#}
#
##module "self_managed_node_group" {
##  source = "../../modules/eks/eks-cluster/modules/self-managed-node-group"
##  providers           = {
##    aws = aws.digio-onetrust
##  }
##
##  name                = "${var.project_name}-sp-self-mng"
##  cluster_name        = module.eks_cluster.cluster_id
##  cluster_version     = module.eks_cluster.cluster_version
##  cluster_endpoint    = module.eks_cluster.cluster_endpoint
##  cluster_auth_base64 = module.eks_cluster.cluster_certificate_authority_data
##
##  instance_type = "m5.large"
##
##  vpc_id     = var.vpc_id
##  subnet_ids = var.private_subnet_ids
##  vpc_security_group_ids = [
##    module.eks_cluster.cluster_primary_security_group_id,
##    module.eks_cluster.cluster_security_group_id,
##  ]
##
##  use_default_tags = true
##
##  tags = merge(var.core_tags,
##    tomap(
##      {"funcao" = "self-managed-node-group"}
##    )
##  )
##}
#
