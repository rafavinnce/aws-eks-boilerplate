locals {
  bastion_user_data = <<-EOT
    #!/bin/bash
  aws s3 cp s3://onetrust-tools/kubectl.zip .
  unzip kubectl.zip
  rm -rf kubectl.zip
  chmod +x ./kubectl
  sudo mv ./kubectl /usr/bin/kubectl
  sudo yum install git -y
  git clone https://github.com/kamatama41/tfenv.git ~/.tfenv
  echo 'export PATH="$HOME/.tfenv/bin:$PATH"' >> ~/.bashrc
  tfenv install 1.2.8
  tfenv use 1.2.8
  sudo yum install -y docker
  sudo usermod -aG docker $USER
  wget https://get.helm.sh/helm-v3.10.2-linux-amd64.tar.gz
  tar -zxvf helm-v3.0.0-linux-amd64.tar.gz
  mv linux-amd64/helm /usr/local/bin/helm
  mv linux-amd64/helm /usr/bin/helm
  rm -rf linux-amd64
  rm -rf helm-v3.10.2-linux-amd64.tar.gz
  EOT
}

module "keypair" {
  providers           = {
    aws = aws.digio-onetrust
  }

  source  = "mitchellh/dynamic-keys/aws"
  version = "2.0.0"
  path    = "keys/${var.environment}"
  name    = "kp-${var.environment}-${var.project_name}"
}

resource "aws_kms_key" "this" {
  enable_key_rotation = "true"
}

module "ec2_bastion" {
  source = "../../modules/ec2"

  providers           = {
    aws = aws.digio-onetrust
  }

  name                        = "${var.environment}-${var.project_name}-bastion"

  ami                         = data.aws_ami.amazon_linux.id
  instance_type               = "t3.large"
  availability_zone           = var.availability_zones_names[0]
  subnet_id                   = var.private_subnet_ids[0]
  vpc_security_group_ids      = [module.security_group_aditional.id]

  user_data_base64            = base64encode(local.bastion_user_data)
  user_data_replace_on_change = true

  enable_volume_tags = false
  root_block_device = [
    {
      encrypted   = true
      volume_type = "gp3"
      throughput  = 200
      volume_size = 50
      tags = {
        Name = "bastion-root-block"
      }
    },
  ]

  ebs_block_device = [
    {
      device_name = "/dev/sdf"
      volume_type = "gp3"
      volume_size = 5
      throughput  = 200
      encrypted   = true
      kms_key_id  = aws_kms_key.this.arn
    }
  ]

  tags = merge(var.core_tags,
    tomap(
      {"funcao" = "eks_ec2_bastion"}
    )
  )
}

module "security_group_aditional" {
  source = "../../modules/security-group"

  providers           = {
    aws = aws.digio-onetrust
  }

  name_prefix     = "${var.environment}-${var.project_name}-aditional"
  vpc_id          = var.vpc_id
  environment     = var.environment
  project_name    = var.project_name

  ingress_rules = [
    {
      protocol      = "tcp"
      from_port     = 22
      to_port       = 22
      description   = "Allow SSH"
      cidr          = ["0.0.0.0/0"],
    },
    {
      protocol      = "tcp"
      from_port     = 80
      to_port       = 80
      description   = "Allow HTTP"
      cidr          = ["0.0.0.0/0"],
    },
    {
      protocol      = "tcp"
      from_port     = 443
      to_port       = 443
      description   = "Allow HTTPS"
      cidr          = ["0.0.0.0/0"],
    },
  ]

  egress_rules = [
    {
      protocol          = "-1"
      from_port         = 0
      to_port           = 0
      description       = "Allow Egress"
      cidr              = ["0.0.0.0/0"],
      ipv6_cidr_blocks  = ["::/0"],
    },
  ]

  core_tags       = merge(var.core_tags,
    tomap(
      {
        "funcao"  = "sg-aditional",
        "Name"    = "${var.environment}-${var.project_name}-aditional"
      }
    )
  )
}