output "arn" {
  value = data.aws_ecr_repository.ecr_data_resource.arn
}

output "repository_url" {
  value = data.aws_ecr_repository.ecr_data_resource.repository_url
}

output "repository_name" {
  value = data.aws_ecr_repository.ecr_data_resource.name
}