data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

data "aws_region" "current" {}

# Made only with create_zone. Otherwise zone_id names a zone that exists.
resource "aws_route53_zone" "this" {
  #checkov:skip=CKV2_AWS_38:DNSSEC needs a KMS key and a DS record at the registrar, which a caller can add for this zone; the module does not assume them.
  #checkov:skip=CKV2_AWS_39:Query logging needs a log group in us-east-1 with its own resource policy, and nothing would read logs of preview hostname lookups.
  count = var.create_zone ? 1 : 0
  name  = var.domain
  tags  = var.tags
}

data "aws_vpc" "default" {
  count   = var.vpc_id == null ? 1 : 0
  default = true
}

data "aws_subnets" "default" {
  count = var.vpc_id == null ? 1 : 0
  filter {
    name   = "vpc-id"
    values = [one(data.aws_vpc.default[*].id)]
  }
  filter {
    name   = "default-for-az"
    values = ["true"]
  }
}

data "aws_ami" "ubuntu" {
  most_recent = true
  owners      = ["099720109477"] # Canonical

  filter {
    name   = "name"
    values = [var.ubuntu_ami_name]
  }
  filter {
    name   = "state"
    values = ["available"]
  }
}

locals {
  account_id   = data.aws_caller_identity.current.account_id
  partition    = data.aws_partition.current.partition
  region       = data.aws_region.current.region
  box_name     = "${var.name_prefix}-box"
  wake_name    = "${var.name_prefix}-wake"
  origin_host  = "origin.${var.domain}"
  uploads_name = "${var.name_prefix}-uploads-${local.account_id}"
  previews_ssm = "/${var.name_prefix}/previews"

  zone_id  = var.create_zone ? aws_route53_zone.this[0].zone_id : var.zone_id
  zone_arn = "arn:${local.partition}:route53:::hostedzone/${local.zone_id}"

  vpc_id    = var.vpc_id != null ? var.vpc_id : one(data.aws_vpc.default[*].id)
  subnet_id = var.subnet_id != null ? var.subnet_id : sort(one(data.aws_subnets.default[*].ids))[0]
}
