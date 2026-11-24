# The koi module: one box, its CloudFront front door, the wake function, the
# uploads bucket and the preview DNS records, in the account and region of the
# aws provider the caller passes. infra/ is the root that uses it for the
# personal deployment; another root uses it the same way (README, "Operating
# it").
#
# No provider or backend block: the caller configures both. aws.us_east_1 is
# for the ACM certificate, which CloudFront takes from us-east-1 only, whatever
# region the box is in.
terraform {
  required_version = ">= 1.5.0"

  required_providers {
    aws = {
      source                = "hashicorp/aws"
      version               = ">= 6.0, < 7.0"
      configuration_aliases = [aws.us_east_1]
    }
    archive = {
      source  = "hashicorp/archive"
      version = ">= 2.7, < 3.0"
    }
  }
}
