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
  #checkov:skip=CKV_AWS_382:Egress is the workload: builds fetch packages and previews call their providers. Previews reach the internet only through the egress proxy inside Docker (host/egress), which is where it is confined.
  name = local.box_name
  # Changing the description replaces the group, so it stays as first
  # written whatever the name prefix.
  description = "koi preview box: HTTPS from CloudFront only"
  vpc_id      = local.vpc_id

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

  tags = merge(var.tags, {
    Name = local.box_name
  })

  lifecycle {
    precondition {
      condition     = (var.vpc_id == null) == (var.subnet_id == null)
      error_message = "Set vpc_id and subnet_id together, or neither for the default VPC."
    }
  }
}
