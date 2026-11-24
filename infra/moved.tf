# The resources below were in this root until they moved into modules/koi.
# These blocks tell OpenTofu to read each existing resource at its new
# address, so the personal state keeps every resource instead of destroying
# and recreating it. They can go once every state made before the move has
# been planned and applied with them.

moved {
  from = aws_iam_role.box
  to   = module.koi.aws_iam_role.box
}

moved {
  from = aws_iam_role_policy.box
  to   = module.koi.aws_iam_role_policy.box
}

moved {
  from = aws_iam_instance_profile.box
  to   = module.koi.aws_iam_instance_profile.box
}

moved {
  from = aws_instance.box
  to   = module.koi.aws_instance.box
}

moved {
  from = aws_eip.box
  to   = module.koi.aws_eip.box
}

moved {
  from = aws_eip_association.box
  to   = module.koi.aws_eip_association.box
}

moved {
  from = aws_ssm_parameter.previews
  to   = module.koi.aws_ssm_parameter.previews
}

moved {
  from = aws_acm_certificate.edge
  to   = module.koi.aws_acm_certificate.edge
}

moved {
  from = aws_route53_record.acm
  to   = module.koi.aws_route53_record.acm
}

moved {
  from = aws_acm_certificate_validation.edge
  to   = module.koi.aws_acm_certificate_validation.edge
}

moved {
  from = aws_cloudfront_origin_access_control.wake
  to   = module.koi.aws_cloudfront_origin_access_control.wake
}

moved {
  from = aws_cloudfront_distribution.edge
  to   = module.koi.aws_cloudfront_distribution.edge
}

moved {
  from = aws_route53_record.wildcard
  to   = module.koi.aws_route53_record.wildcard
}

moved {
  from = aws_route53_record.apex
  to   = module.koi.aws_route53_record.apex
}

moved {
  from = aws_route53_record.origin
  to   = module.koi.aws_route53_record.origin
}

moved {
  from = aws_security_group.box
  to   = module.koi.aws_security_group.box
}

moved {
  from = aws_s3_bucket.uploads
  to   = module.koi.aws_s3_bucket.uploads
}

moved {
  from = aws_s3_bucket_public_access_block.uploads
  to   = module.koi.aws_s3_bucket_public_access_block.uploads
}

moved {
  from = aws_s3_bucket_server_side_encryption_configuration.uploads
  to   = module.koi.aws_s3_bucket_server_side_encryption_configuration.uploads
}

moved {
  from = aws_s3_bucket_lifecycle_configuration.uploads
  to   = module.koi.aws_s3_bucket_lifecycle_configuration.uploads
}

moved {
  from = aws_cloudwatch_log_group.wake
  to   = module.koi.aws_cloudwatch_log_group.wake
}

moved {
  from = aws_iam_role.wake
  to   = module.koi.aws_iam_role.wake
}

moved {
  from = aws_iam_role_policy.wake
  to   = module.koi.aws_iam_role_policy.wake
}

moved {
  from = aws_lambda_function.wake
  to   = module.koi.aws_lambda_function.wake
}

moved {
  from = aws_lambda_function_url.wake
  to   = module.koi.aws_lambda_function_url.wake
}

moved {
  from = aws_lambda_permission.wake_url_from_cloudfront
  to   = module.koi.aws_lambda_permission.wake_url_from_cloudfront
}

moved {
  from = aws_lambda_permission.wake_from_cloudfront
  to   = module.koi.aws_lambda_permission.wake_from_cloudfront
}
