variable "name" {
  description = "The name"
}

variable "core_tags" {
  type = map(string)
}

variable "mount_target_subnet" { }
variable "encrypted" { }
