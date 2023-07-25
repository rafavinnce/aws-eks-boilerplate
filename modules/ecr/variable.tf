variable "environment" {
  description = "The environment"
}

variable "name" {
  description = "The name"
}

variable "project_name" {
  description = "The name of the project"
}

variable "image_tag_mutability" {
  description = "Mutability"
}

variable "image_scanning_configuration" {
  description = "image_scanning_configuration"
}

variable "core_tags" {
  type = map(string)
}