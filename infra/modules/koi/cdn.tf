# ---------------------------------------------------------------------------
# CloudFront is the one stable address. It forwards to the box; when the box
# is stopped the origin fails, CloudFront serves the wake page from the wake
# function instead, and that page starts the box and reloads when it answers.
# ---------------------------------------------------------------------------

data "aws_cloudfront_cache_policy" "caching_disabled" {
  name = "Managed-CachingDisabled"
}

data "aws_cloudfront_origin_request_policy" "all_viewer" {
  name = "Managed-AllViewer"
}

data "aws_cloudfront_origin_request_policy" "all_viewer_except_host" {
  name = "Managed-AllViewerExceptHostHeader"
}

# CloudFront takes its certificate from us-east-1 only, so this and its
# validation use the us_east_1 provider whatever region the box is in.
resource "aws_acm_certificate" "edge" {
  provider                  = aws.us_east_1
  domain_name               = "*.${var.domain}"
  subject_alternative_names = [var.domain]
  validation_method         = "DNS"
  tags                      = var.tags

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_route53_record" "acm" {
  for_each = {
    for dvo in aws_acm_certificate.edge.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  zone_id         = local.zone_id
  name            = each.value.name
  type            = each.value.type
  ttl             = 60
  records         = [each.value.record]
}

resource "aws_acm_certificate_validation" "edge" {
  provider                = aws.us_east_1
  certificate_arn         = aws_acm_certificate.edge.arn
  validation_record_fqdns = [for r in aws_route53_record.acm : r.fqdn]
}

# Lets CloudFront call the wake function's URL with SigV4, so the URL itself
# is not publicly invokable.
resource "aws_cloudfront_origin_access_control" "wake" {
  name                              = local.wake_name
  origin_access_control_origin_type = "lambda"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

locals {
  wake_origin_host = trimsuffix(trimprefix(aws_lambda_function_url.wake.function_url, "https://"), "/")
}

resource "aws_cloudfront_distribution" "edge" {
  #checkov:skip=CKV_AWS_68:No WAF. The box serves pull-request previews to reviewers, and the managed rule sets would block requests a preview app legitimately makes; koid only counts requests for live previews as activity.
  #checkov:skip=CKV2_AWS_47:No WAF, as for CKV_AWS_68, so no Log4j rule set either.
  #checkov:skip=CKV_AWS_86:No access log bucket. Previews are short-lived review builds, and Caddy on the box logs what reaches it.
  #checkov:skip=CKV_AWS_310:The wake function is the failover: CloudFront serves it on 502 and 504 from the box (custom_error_response below). An origin group cannot carry that.
  #checkov:skip=CKV_AWS_374:Reviewers may be anywhere; nothing here is region-restricted.
  #checkov:skip=CKV2_AWS_32:A response headers policy would overwrite the security headers each preview app sets for itself.
  #checkov:skip=CKV_AWS_305:A reverse proxy for many hostnames has no root object; every path goes to the box.
  enabled         = true
  is_ipv6_enabled = true
  comment         = "${var.name_prefix} previews"
  http_version    = "http2and3"
  price_class     = "PriceClass_100"
  aliases         = ["*.${var.domain}", var.domain]
  tags            = var.tags

  origin {
    origin_id   = "box"
    domain_name = local.origin_host
    # Fail over fast: a stopped box never answers the SYN, so wait two seconds
    # once rather than the default ten seconds three times.
    connection_attempts = 1
    connection_timeout  = 2

    custom_origin_config {
      http_port                = 80
      https_port               = 443
      origin_protocol_policy   = "https-only"
      origin_ssl_protocols     = ["TLSv1.2"]
      origin_read_timeout      = 60
      origin_keepalive_timeout = 60
    }
  }

  origin {
    origin_id                = "wake"
    domain_name              = local.wake_origin_host
    origin_access_control_id = aws_cloudfront_origin_access_control.wake.id

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  # Everything goes to the box uncached, with the viewer's Host header intact
  # so Caddy routes to the right preview. WebSocket upgrades pass through.
  default_cache_behavior {
    target_origin_id         = "box"
    viewer_protocol_policy   = "redirect-to-https"
    allowed_methods          = ["GET", "HEAD", "OPTIONS", "PUT", "POST", "PATCH", "DELETE"]
    cached_methods           = ["GET", "HEAD"]
    cache_policy_id          = data.aws_cloudfront_cache_policy.caching_disabled.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_viewer.id
    compress                 = false
  }

  # The wake page and its API. Host must not be forwarded here: a function URL
  # only answers to its own hostname.
  ordered_cache_behavior {
    path_pattern             = "/__koi-wake/*"
    target_origin_id         = "wake"
    viewer_protocol_policy   = "https-only"
    allowed_methods          = ["GET", "HEAD", "OPTIONS"]
    cached_methods           = ["GET", "HEAD"]
    cache_policy_id          = data.aws_cloudfront_cache_policy.caching_disabled.id
    origin_request_policy_id = data.aws_cloudfront_origin_request_policy.all_viewer_except_host.id
    compress                 = true
  }

  # A stopped box never answers the SYN (CloudFront returns 504), a booting box
  # refuses the connection (502), and Caddy answers 502 while koid is down. 503
  # is deliberately left out: CloudFront replaces matching responses from the
  # app too, and 503 is a status real apps send. The cost is that a preview's
  # own 502 or 504 also shows the wake page.
  dynamic "custom_error_response" {
    for_each = [502, 504]
    content {
      error_code            = custom_error_response.value
      response_code         = 503
      response_page_path    = "/__koi-wake/index.html"
      error_caching_min_ttl = 0
    }
  }

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    acm_certificate_arn      = aws_acm_certificate_validation.edge.certificate_arn
    ssl_support_method       = "sni-only"
    minimum_protocol_version = "TLSv1.2_2021"
  }
}
