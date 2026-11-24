variable "region" {
  type    = string
  default = "us-east-1"
}

# No default: every deployment names its own domain. Copy
# infra/koi.auto.tfvars.example to infra/koi.auto.tfvars and set it there.
# The account must hold its Route 53 hosted zone. The module checks the value.
variable "domain" {
  description = "Base domain; previews live at <label>.<domain>."
  type        = string
}

# Unset (null) takes the module's default; modules/koi/variables.tf describes
# each and checks the values.

variable "instance_type" {
  type    = string
  default = null
}

variable "root_volume_gb" {
  type    = number
  default = null
}

variable "ubuntu_ami_name" {
  type    = string
  default = null
}

variable "verify_pool" {
  type    = string
  default = null
}
