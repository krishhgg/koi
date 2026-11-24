# scripts/deploy-host.sh and scripts/provision-host.sh read these with
# `tofu output` when the matching KOI_* variable is not set.

output "box_instance_id" {
  value = module.koi.instance_id
}

output "box_public_ip" {
  value = module.koi.box_public_ip
}

output "uploads_bucket" {
  value = module.koi.uploads_bucket
}

output "cloudfront_domain" {
  value = module.koi.cloudfront_domain
}

output "wake_function_url" {
  value = module.koi.wake_function_url
}

output "previews_parameter" {
  value = module.koi.previews_parameter
}

# scripts/deploy-host.sh writes it to /etc/koi/env; scripts/provision-host.sh
# hands it to host/cloud-init.sh.
output "domain" {
  value = module.koi.domain
}

# scripts/provision-host.sh hands it to host/cloud-init.sh with the domain.
output "verify_pool" {
  value = module.koi.verify_pool
}

output "region" {
  value = module.koi.region
}
