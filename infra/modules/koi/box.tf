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
  name               = local.box_name
  assume_role_policy = data.aws_iam_policy_document.box_assume.json
  tags               = var.tags
}

data "aws_iam_policy_document" "box" {
  #checkov:skip=CKV_AWS_111:The SSM agent's registration and messaging actions and Route 53's ListHostedZones have no resource-level scoping; every other statement names its resource.
  #checkov:skip=CKV_AWS_356:Same statements as CKV_AWS_111: the SsmAgent and AcmeFindZone actions take only "*".
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
    resources = [local.zone_arn]
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
    resources = [local.zone_arn]
  }
  statement {
    sid       = "AcmeChangeStatus"
    actions   = ["route53:GetChange"]
    resources = ["arn:${local.partition}:route53:::change/*"]
  }
  # ListHostedZonesByName has no resource-level scoping in IAM.
  statement {
    sid       = "AcmeFindZone"
    actions   = ["route53:ListHostedZonesByName", "route53:ListHostedZones"]
    resources = ["*"]
  }
}

resource "aws_iam_role_policy" "box" {
  name   = local.box_name
  role   = aws_iam_role.box.id
  policy = data.aws_iam_policy_document.box.json
}

resource "aws_iam_instance_profile" "box" {
  name = local.box_name
  role = aws_iam_role.box.name
  tags = var.tags
}

resource "aws_instance" "box" {
  #checkov:skip=CKV_AWS_135:t3 and the other Nitro types are EBS-optimized by default, and setting ebs_optimized on a box made without it replaces the box, which wipes its build caches.
  ami                    = data.aws_ami.ubuntu.id
  instance_type          = var.instance_type
  subnet_id              = local.subnet_id
  vpc_security_group_ids = [aws_security_group.box.id]
  iam_instance_profile   = aws_iam_instance_profile.box.name

  # One-minute CloudWatch metrics while the box runs.
  monitoring = true

  # `shutdown -h now` on the box stops the instance instead of terminating it.
  instance_initiated_shutdown_behavior = "stop"

  # Runs once, at first boot. Changing it does not re-run it on this box; use
  # scripts/provision-host.sh to apply host changes to a running box. Gzipped,
  # because EC2 caps user data at 16 KiB and the script is larger; cloud-init
  # unpacks it before running it. The script reads the domain from KOI_DOMAIN,
  # the verification pool from KOI_VERIFY_POOL and the region from KOI_REGION,
  # set on the lines in front of it; provision-host.sh prepends the same lines.
  # files/cloud-init.sh links to host/cloud-init.sh; a copy of the module
  # made with `cp -rL` carries the file itself.
  user_data_base64 = base64gzip(join("\n", [
    "#!/bin/bash",
    "KOI_DOMAIN=${var.domain}",
    "KOI_VERIFY_POOL=${var.verify_pool}",
    "KOI_REGION=${local.region}",
    file("${path.module}/files/cloud-init.sh"),
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

  # Without a config file the CLI finds the box by koi:role and reads the
  # preview domain from Domain, so a team needs no settings beyond an AWS
  # profile. koi:role rather than Project, which the caller's default_tags
  # may set to anything.
  tags = merge(var.tags, {
    Name       = local.box_name
    Domain     = var.domain
    "koi:role" = "box"
  })

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
  tags = merge(var.tags, {
    Name = local.box_name
  })
}

resource "aws_eip_association" "box" {
  instance_id   = aws_instance.box.id
  allocation_id = aws_eip.box.id
}

# Labels of previews that may wake the box. The daemon writes it; the wake
# function reads it. Seeded empty here and never overwritten by apply.
resource "aws_ssm_parameter" "previews" {
  #checkov:skip=CKV2_AWS_34:Holds the labels of live previews, which are public hostnames, not secrets; the wake function and the box read it as plain JSON.
  name  = local.previews_ssm
  type  = "String"
  value = "[]"
  tags  = var.tags

  lifecycle {
    ignore_changes = [value]
  }
}
