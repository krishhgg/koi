terraform {
  required_version = ">= 1.8"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.7"
    }
  }

  # Bucket and key come from backend.hcl, which infra/bootstrap.sh writes for
  # the current account (backend.hcl.example shows its shape):
  # `tofu init -backend-config=backend.hcl`.
  # CI runs `init -backend=false`, so no credentials are needed to validate.
  backend "s3" {}
}
