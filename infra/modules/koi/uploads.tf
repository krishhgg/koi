# Source tarballs from `koi up`, and host bundles from scripts/deploy-host.sh
# under host/. Objects expire after a day; the box pulls them within seconds
# of upload.
resource "aws_s3_bucket" "uploads" {
  #checkov:skip=CKV_AWS_18:Objects live a day and only operators write them; a log bucket would outlive everything it records.
  #checkov:skip=CKV_AWS_144:Source tarballs that expire after a day are not worth a second region.
  #checkov:skip=CKV2_AWS_62:Nothing subscribes: the CLI tells koid about each upload through SSM.
  #checkov:skip=CKV_AWS_21:Each object is written once under a fresh key and expires after a day, so there is nothing to version.
  bucket = local.uploads_name
  # Everything here is a one-day upload (the lifecycle rule below), so a
  # destroy removes what is left rather than stopping on BucketNotEmpty, which
  # it otherwise does after the first deploy-host.sh or koi up. The provider reads
  # this from state when it deletes, so a state applied without it needs one
  # apply first.
  force_destroy = true
  tags          = var.tags
}

resource "aws_s3_bucket_public_access_block" "uploads" {
  bucket                  = aws_s3_bucket.uploads.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  # The account's AWS managed key for S3, whose key policy lets every
  # principal in the account use it through S3, so the CLI, the box role and
  # presigned URLs need no KMS permissions. The bucket key keeps KMS calls to
  # about one per object batch.
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_lifecycle_configuration" "uploads" {
  bucket = aws_s3_bucket.uploads.id
  rule {
    id     = "expire-uploads"
    status = "Enabled"
    filter {}
    expiration {
      days = 1
    }
    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}
