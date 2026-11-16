# *.<domain> and the apex point at CloudFront; origin.<domain> points at the
# box's fixed IP and is only ever dialled by CloudFront.

resource "aws_route53_record" "wildcard" {
  for_each = toset(["A", "AAAA"])
  zone_id  = data.aws_route53_zone.root.zone_id
  name     = "*.${var.domain}"
  type     = each.value

  alias {
    name                   = aws_cloudfront_distribution.edge.domain_name
    zone_id                = aws_cloudfront_distribution.edge.hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "apex" {
  for_each = toset(["A", "AAAA"])
  zone_id  = data.aws_route53_zone.root.zone_id
  name     = var.domain
  type     = each.value

  alias {
    name                   = aws_cloudfront_distribution.edge.domain_name
    zone_id                = aws_cloudfront_distribution.edge.hosted_zone_id
    evaluate_target_health = false
  }
}

resource "aws_route53_record" "origin" {
  zone_id = data.aws_route53_zone.root.zone_id
  name    = local.origin_host
  type    = "A"
  ttl     = 60
  records = [aws_eip.box.public_ip]
}
