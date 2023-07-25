data "aws_caller_identity" "current" { }

data "aws_ami" "lin_ami" {
  most_recent = true
  owners = ["amazon"]
  filter {
    name = "name"
    values = ["amazon-eks-node-${var.cluster_version}-*"]
  }
}

data "aws_ami" "win_ami" {
  most_recent = true
  owners = ["amazon"]
  filter {
    name = "name"
    values = ["Windows_Server-2022-*"]
  }
}

data "aws_ami" "amazon_linux" {
  most_recent = true
  owners      = ["amazon"]

  filter {
    name   = "name"
    values = ["amzn-ami-hvm-*-x86_64-gp2"]
  }
}