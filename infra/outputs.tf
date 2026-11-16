output "box_instance_id" {
  value = aws_instance.box.id
}

output "box_public_ip" {
  value = aws_eip.box.public_ip
}

output "uploads_bucket" {
  value = aws_s3_bucket.uploads.bucket
}

output "cloudfront_domain" {
  value = aws_cloudfront_distribution.edge.domain_name
}

output "wake_function_url" {
  value = aws_lambda_function_url.wake.function_url
}

output "previews_parameter" {
  value = aws_ssm_parameter.previews.name
}

# scripts/deploy-host.sh writes it to /etc/koi/env; scripts/provision-host.sh
# hands it to host/cloud-init.sh.
output "domain" {
  value = var.domain
}

# scripts/provision-host.sh hands it to host/cloud-init.sh with the domain.
output "verify_pool" {
  value = var.verify_pool
}
