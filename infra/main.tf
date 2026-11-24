# The personal deployment: the koi module (modules/koi) in the account
# infra/bootstrap.sh runs in, plus the koi-cli user (users.tf). Another root,
# such as a company's, calls the same module with its own providers, backend
# and tags (README, "Operating it").

provider "aws" {
  region = var.region

  default_tags {
    tags = {
      Project = "koi"
    }
  }
}

# For the ACM certificate, which CloudFront takes from us-east-1 only.
provider "aws" {
  alias  = "us_east_1"
  region = "us-east-1"

  default_tags {
    tags = {
      Project = "koi"
    }
  }
}

# The hosted zone was made by hand, outside this state.
data "aws_route53_zone" "root" {
  name = var.domain
}

module "koi" {
  source = "./modules/koi"
  providers = {
    aws           = aws
    aws.us_east_1 = aws.us_east_1
  }

  domain          = var.domain
  zone_id         = data.aws_route53_zone.root.zone_id
  instance_type   = var.instance_type
  root_volume_gb  = var.root_volume_gb
  ubuntu_ami_name = var.ubuntu_ami_name
  verify_pool     = var.verify_pool

  wake_reserved_concurrency = var.wake_reserved_concurrency
}
