# Inbound is 443 from CloudFront only, so nothing on the internet can reach
# Caddy except through the distribution. That does not make every request a
# real visit: CloudFront forwards anyone's request for any *.<domain> name,
# so koid decides what counts as activity (only requests for live previews).
# The CLI reaches the box through SSM, never SSH, and Caddy gets its
# certificate by DNS-01, so port 80 is not needed either.
data "aws_ec2_managed_prefix_list" "cloudfront_origin_facing" {
  name = "com.amazonaws.global.cloudfront.origin-facing"
}

resource "aws_security_group" "box" {
  name        = "koi-box"
  description = "koi preview box: HTTPS from CloudFront only"
  vpc_id      = data.aws_vpc.default.id

  # The prefix list weighs about 55 rules against the 60-rule default quota,
  # so this group has room for very little else.
  ingress {
    description     = "HTTPS from CloudFront origin-facing addresses"
    from_port       = 443
    to_port         = 443
    protocol        = "tcp"
    prefix_list_ids = [data.aws_ec2_managed_prefix_list.cloudfront_origin_facing.id]
  }

  egress {
    description      = "all outbound (previews are confined separately, inside Docker)"
    from_port        = 0
    to_port          = 0
    protocol         = "-1"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }

  tags = {
    Name = "koi-box"
  }
}
