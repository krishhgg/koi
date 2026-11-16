# ---------------------------------------------------------------------------
# The one instance. Stopped most of the time; the wake function starts it and
# it stops itself after idling (instance_initiated_shutdown_behavior = stop).
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "box_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "box" {
  name               = "koi-box"
  assume_role_policy = data.aws_iam_policy_document.box_assume.json
}

data "aws_iam_policy_document" "box" {
  # What the SSM agent needs to register and take Run Command jobs. Written out
  # instead of attaching AmazonSSMManagedInstanceCore, which also grants
  # ssm:GetParameter(s) on every parameter in the account.
  statement {
    sid = "SsmAgent"
    actions = [
      "ssm:UpdateInstanceInformation",
      "ssm:ListInstanceAssociations",
      "ssm:DescribeAssociation",
      "ssm:GetDocument",
      "ssm:DescribeDocument",
      "ssm:UpdateAssociationStatus",
      "ssm:UpdateInstanceAssociationStatus",
      "ssm:PutInventory",
      "ssm:PutComplianceItems",
      "ec2messages:AcknowledgeMessage",
      "ec2messages:DeleteMessage",
      "ec2messages:FailMessage",
      "ec2messages:GetEndpoint",
      "ec2messages:GetMessages",
      "ec2messages:SendReply",
      "ssmmessages:CreateControlChannel",
      "ssmmessages:CreateDataChannel",
      "ssmmessages:OpenControlChannel",
      "ssmmessages:OpenDataChannel",
    ]
    # These actions have no resource-level scoping for the calling instance.
    resources = ["*"]
  }

  # Source tarballs the CLI uploads.
  statement {
    sid       = "ReadUploads"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.uploads.arn}/*"]
  }
  statement {
    sid       = "ListUploads"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.uploads.arn]
  }

  # The live-preview list the wake function consults.
  statement {
    sid       = "PreviewList"
    actions   = ["ssm:GetParameter", "ssm:PutParameter"]
    resources = [aws_ssm_parameter.previews.arn]
  }

  # Caddy's ACME DNS-01 challenge for the wildcard certificate: only the one
  # TXT record ACME uses, so the box cannot touch SPF, DKIM or verification
  # records elsewhere in the zone.
  statement {
    sid       = "AcmeTxtRecords"
    actions   = ["route53:ChangeResourceRecordSets"]
    resources = [data.aws_route53_zone.root.arn]
    condition {
      test     = "ForAllValues:StringEquals"
      variable = "route53:ChangeResourceRecordSetsRecordTypes"
      values   = ["TXT"]
    }
    condition {
      test     = "ForAllValues:StringEquals"
      variable = "route53:ChangeResourceRecordSetsNormalizedRecordNames"
      values   = ["_acme-challenge.${var.domain}"]
    }
  }
  statement {
    sid       = "AcmeReadZone"
    actions   = ["route53:ListResourceRecordSets"]
    resources = [data.aws_route53_zone.root.arn]
  }
  statement {
    sid       = "AcmeChangeStatus"
    actions   = ["route53:GetChange"]
    resources = ["arn:aws:route53:::change/*"]
  }
  # ListHostedZonesByName has no resource-level scoping in IAM.
  statement {
    sid       = "AcmeFindZone"
    actions   = ["route53:ListHostedZonesByName", "route53:ListHostedZones"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "box" {
  name   = "koi-box"
  role   = aws_iam_role.box.id
  policy = data.aws_iam_policy_document.box.json
}

resource "aws_iam_instance_profile" "box" {
  name = "koi-box"
  role = aws_iam_role.box.name
}

resource "aws_instance" "box" {
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = sort(data.aws_subnets.default.ids)[0]
  vpc_security_group_ids = [aws_security_group.box.id]
  iam_instance_profile   = aws_iam_instance_profile.box.name

  # `shutdown -h now` on the box stops the instance instead of terminating it.
  instance_initiated_shutdown_behavior = "stop"

  # Runs once, at first boot. Changing it does not re-run it on this box; use
  # scripts/provision-host.sh to apply host changes to a running box. Gzipped,
  # because EC2 caps user data at 16 KiB and the script is larger; cloud-init
  # unpacks it before running it. The script reads the domain from KOI_DOMAIN
  # and the verification pool from KOI_VERIFY_POOL, set on the lines in front
  # of it; provision-host.sh prepends the same lines.
  user_data_base64 = base64gzip(join("\n", [
    "#!/bin/bash",
    "KOI_DOMAIN=${var.domain}",
    "KOI_VERIFY_POOL=${var.verify_pool}",
    file("${path.module}/../host/cloud-init.sh"),
  ]))
  user_data_replace_on_change = false

  root_block_device {
    volume_size = var.root_volume_gb
    volume_type = "gp3"
    encrypted   = true
  }

  # IMDSv2 only, and a hop limit of 1 so containers behind Docker's NAT cannot
  # reach the metadata endpoint and the instance role's credentials.
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  # The CLI finds the box by Name and reads the preview domain from Domain,
  # so a team needs no settings beyond an AWS profile.
  tags = {
    Name   = "koi-box"
    Domain = var.domain
  }

  lifecycle {
    # A newer AMI or a reordered subnet list must not replace the box and wipe
    # its caches; rebuilds are deliberate. User data only runs at first boot,
    # so a change to it would only stop and start the box for nothing; host
    # changes reach a running box through scripts/provision-host.sh.
    ignore_changes = [ami, subnet_id, user_data, user_data_base64]
  }
}

# Fixed address so CloudFront's origin hostname never changes.
resource "aws_eip" "box" {
  domain = "vpc"
  tags = {
    Name = "koi-box"
  }
}

resource "aws_eip_association" "box" {
  instance_id   = aws_instance.box.id
  allocation_id = aws_eip.box.id
}

# Labels of previews that may wake the box. The daemon writes it; the wake
# function reads it. Seeded empty here and never overwritten by apply.
resource "aws_ssm_parameter" "previews" {
  name  = local.previews_ssm
  type  = "String"
  value = "[]"

  lifecycle {
    ignore_changes = [value]
  }
}
