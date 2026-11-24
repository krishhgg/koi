# Variables with a default are not nullable: a caller that passes null gets
# the default, so a root can pass its own optional variables straight through.

variable "domain" {
  description = "Base domain; previews live at <label>.<domain>. Its Route 53 hosted zone must be in the same account: zone_id names it, or create_zone makes it."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9.-]+$", var.domain))
    error_message = "domain must be a bare hostname: lowercase letters, digits, dots and hyphens, as in previews.example.com."
  }
}

variable "zone_id" {
  description = "ID of the Route 53 hosted zone for domain. Set this, or create_zone = true."
  type        = string
  default     = null

  validation {
    condition     = var.zone_id == null || can(regex("^Z[A-Z0-9]+$", var.zone_id))
    error_message = "zone_id must be a hosted zone ID, as in Z0123456789ABCDEFGHIJ."
  }
}

variable "create_zone" {
  description = "Create the hosted zone for domain in this account. The registrar must then delegate to the zone's name servers (output name_servers) before the certificate can validate."
  type        = bool
  default     = false
  nullable    = false
}

variable "name_prefix" {
  description = "Prefix of every resource name: <prefix>-box, <prefix>-wake, <prefix>-uploads-<account>, /<prefix>/previews. The CLI's discovery without a config file assumes koi-uploads-<account>; with another prefix, name the bucket in the CLI's target."
  type        = string
  default     = "koi"
  nullable    = false

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{0,29}$", var.name_prefix))
    error_message = "name_prefix must start with a lowercase letter and hold at most 30 lowercase letters, digits and hyphens."
  }
}

variable "instance_type" {
  type     = string
  default  = "t3.xlarge"
  nullable = false
}

variable "root_volume_gb" {
  type     = number
  default  = 80
  nullable = false
}

variable "ubuntu_ami_name" {
  description = "Name pattern for the Ubuntu AMI. The box keeps its AMI after first boot (see lifecycle on aws_instance.box)."
  type        = string
  default     = "ubuntu/images/hvm-ssd-gp3/ubuntu-noble-24.04-amd64-server-*"
  nullable    = false
}

variable "vpc_id" {
  description = "VPC for the box. Set it together with subnet_id, or leave both unset for the region's default VPC."
  type        = string
  default     = null
}

variable "subnet_id" {
  description = "Subnet for the box, in vpc_id. It needs a route to an internet gateway: the box's Elastic IP is how CloudFront and the SSM agent reach it."
  type        = string
  default     = null
}

variable "tags" {
  description = "Tags for every resource that takes them, on top of the provider's default_tags. The box also gets Name, Domain and koi:role = box, which the CLI finds it by."
  type        = map(string)
  default     = {}
  nullable    = false
}

variable "wake_reserved_concurrency" {
  description = "Concurrent executions reserved for the wake function, which also caps them. null (the default) leaves it unreserved. Lambda keeps 100 of an account's concurrency unreserved in each region, so a reservation fails where other functions already hold all but 100 + this many, and in an account still on the new-account quota of 10."
  type        = number
  default     = null
}

# The addresses verification run networks are carved from, a /28 each
# (docs/verify.md, "Run network"). Provisioning writes it to the box; it must
# not overlap the VPC or the subnets Docker gives koi-previews and koi-build
# (172.17.0.0/12 and 192.168.0.0/16 by default).
variable "verify_pool" {
  description = "IPv4 network reserved for verification run networks, between a /16 and a /28, as its network address."
  type        = string
  default     = "10.213.0.0/20"
  nullable    = false

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
