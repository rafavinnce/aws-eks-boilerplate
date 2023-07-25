resource "aws_efs_file_system" "this" {
  creation_token = var.name
  encrypted = var.encrypted
  tags = merge(var.core_tags,
    tomap(
      {
        "Name" = var.name,
        "funcao" = "efs"
      }
    )
  )
}

resource "aws_efs_mount_target" "this" {
  file_system_id = aws_efs_file_system.this.id
  subnet_id      = var.mount_target_subnet
  security_groups = ["sg-035f79c776f5de3ba"]

  depends_on = [aws_efs_file_system.this]
}

resource "aws_efs_mount_target" "this02" {
  file_system_id = aws_efs_file_system.this.id
  subnet_id      = "subnet-0489be1815252a915"
  security_groups = ["sg-035f79c776f5de3ba"]

  depends_on = [aws_efs_file_system.this]
}

resource "aws_efs_mount_target" "this03" {
  file_system_id = aws_efs_file_system.this.id
  subnet_id      = "subnet-0a024ec1653a0a513"
  security_groups = ["sg-035f79c776f5de3ba"]

  depends_on = [aws_efs_file_system.this]
}
