provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project = "koi"
    }
  }
}

data "aws_caller_identity" "current" {}

data "aws_route53_zone" "root" {
  name = var.domain
}

data "aws_vpc" "default" {
  default = true
}

data "aws_subnets" "default" {
  filter {
    name   = "vpc-id"
    values = [data.aws_vpc.default.id]
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
  origin_host  = "origin.${var.domain}"
  uploads_name = "koi-uploads-${local.account_id}"
  previews_ssm = "/koi/previews"
}
