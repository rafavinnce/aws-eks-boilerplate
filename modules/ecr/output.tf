output "arn" {
  value = aws_ecr_repository.ecr_resource.arn
}

output "repository_url" {
  value = aws_ecr_repository.ecr_resource.repository_url
}

output "repository_name" {
  value = aws_ecr_repository.ecr_resource.name
}