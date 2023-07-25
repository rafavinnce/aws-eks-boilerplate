/*====
Secrets
======*/

resource "aws_secretsmanager_secret" "secrets" {
  name                    = var.name
  description             = "Secrets for ${var.project_name} ${var.environment}"
  policy                  = data.template_file.secret_policy.rendered
  tags = merge(var.core_tags,
    tomap(
      {"funcao" = "secretsmanager"}
    )
  )
}

data "template_file" "secret_policy" {
  template = file("${path.module}/policies/secret-policy.json")
  vars = {
    account_id              = var.account_id
  }
}

resource "aws_secretsmanager_secret_version" "secret" {
  secret_id = aws_secretsmanager_secret.secrets.id
  secret_string = jsonencode(var.secret_keys)
}
//resource "aws_secretsmanager_secret_version" "secret" {
//  secret_id = aws_secretsmanager_secret.secrets.id
//  secret_string = "temporario"
//}