variable "region" {
  type    = string
  default = "us-east-1"
}

# No default: every deployment names its own domain. Copy
# infra/koi.auto.tfvars.example to infra/koi.auto.tfvars and set it there.
variable "domain" {
  description = "Base domain; previews live at <label>.<domain>. The account must hold its Route 53 hosted zone."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9.-]+$", var.domain))
    error_message = "domain must be a bare hostname: lowercase letters, digits, dots and hyphens, as in previews.example.com."
  }
}

variable "instance_type" {
  type    = string
  default = "t3.xlarge"
}

variable "root_volume_gb" {
  type    = number
  default = 80
}

variable "ubuntu_ami_name" {
  description = "Name pattern for the Ubuntu AMI. The box keeps its AMI after first boot (see lifecycle on aws_instance.box)."
  type        = string
  default     = "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"
}

# The addresses verification run networks are carved from, a /28 each
# (docs/verify.md, "Run network"). Provisioning writes it to the box; it must
# not overlap the VPC or the subnets Docker gives koi-previews and koi-build
# (172.17.0.0/12 and 192.168.0.0/16 by default).
variable "verify_pool" {
  description = "IPv4 network reserved for verification run networks, between a /16 and a /28, as its network address."
  type        = string
  default     = "10.213.0.0/20"

  validation {
    condition     = can(cidrnetmask(var.verify_pool)) && tonumber(split("/", var.verify_pool)[1]) >= 16 && tonumber(split("/", var.verify_pool)[1]) <= 28
    error_message = "verify_pool must be an IPv4 network between a /16 and a /28, as in 10.213.0.0/20."
  }

  # koid reads the value as KOI_VERIFY_POOL and takes a network address
  # alone: 10.213.0.1/20 names a host, and would make verification
  # unavailable on the box. try() passes a value that is no CIDR at all on
  # to the check above, which names that problem.
  validation {
    condition     = try(cidrsubnet(var.verify_pool, 0, 0), var.verify_pool) == var.verify_pool
    error_message = "verify_pool must be the network address, with its host bits clear: 10.213.0.0/20, not 10.213.0.1/20."
  }
}
