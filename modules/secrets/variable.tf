variable "environment" {
  description = "The environment"
}

variable "project_name" {
  description = "The name of the project "
}

variable "name" {
  description = "The name of the resource "
}

variable "kms_key_id" {
  default = ""
}
variable "account_id" {
}
variable "secret_keys" {
  type = map(string)
}

variable "core_tags" {
  type = map(string)
}
