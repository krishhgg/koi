# scripts/deploy-host.sh and scripts/provision-host.sh take these as
# KOI_INSTANCE_ID, KOI_BUCKET, KOI_PREVIEWS_PARAM, KOI_DOMAIN and
# KOI_VERIFY_POOL, and the CLI's target names the instance and the bucket.

output "instance_id" {
  value = aws_instance.box.id
}

output "box_public_ip" {
  value = aws_eip.box.public_ip
}

output "uploads_bucket" {
  value = aws_s3_bucket.uploads.bucket
}

output "previews_parameter" {
  value = aws_ssm_parameter.previews.name
}

output "domain" {
  value = var.domain
}

output "verify_pool" {
  value = var.verify_pool
}

output "region" {
  value = local.region
}

output "cloudfront_domain" {
  value = aws_cloudfront_distribution.edge.domain_name
}

output "wake_function_url" {
  value = aws_lambda_function_url.wake.function_url
}

output "zone_id" {
  value = local.zone_id
}

# The registrar's name servers for domain, when the module made the zone.
output "name_servers" {
  value = var.create_zone ? aws_route53_zone.this[0].name_servers : null
}

# Start and describe the box, run shell commands on it through SSM, upload
# source to the bucket and read the preview list (operator.tf).
output "operator_policy_json" {
  value = data.aws_iam_policy_document.operator.json
}
