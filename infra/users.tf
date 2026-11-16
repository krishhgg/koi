# ---------------------------------------------------------------------------
# koi-cli: what `koi up` needs and nothing else. Its access key is created by
# infra/bootstrap.sh, outside the state file.
#
# There is deliberately no deploy user. Any policy broad enough to run
# `tofu apply` (create roles, attach policies) is broad enough to grant itself
# administrator, so a scoped deploy user protects nothing. Infrastructure is
# applied with the operator's own short-lived admin session (`aws login`).
# ---------------------------------------------------------------------------

resource "aws_iam_user" "cli" {
  name = "koi-cli"
}

data "aws_iam_policy_document" "cli" {
  statement {
    sid       = "UploadSource"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.uploads.arn}/*"]
  }
  statement {
    sid     = "RunOnBox"
    actions = ["ssm:SendCommand"]
    resources = [
      aws_instance.box.arn,
      "arn:aws:ssm:${var.region}::document/AWS-RunShellScript",
    ]
  }
  # Command results are not resource-scopable.
  statement {
    sid       = "ReadCommandResults"
    actions   = ["ssm:GetCommandInvocation", "ssm:ListCommandInvocations"]
    resources = ["*"]
  }
  statement {
    sid       = "StartBox"
    actions   = ["ec2:StartInstances"]
    resources = [aws_instance.box.arn]
  }
  # Describe calls are not resource-scopable.
  statement {
    sid       = "DescribeBox"
    actions   = ["ec2:DescribeInstances", "ec2:DescribeInstanceStatus", "ssm:DescribeInstanceInformation"]
    resources = ["*"]
  }
  statement {
    sid       = "PreviewList"
    actions   = ["ssm:GetParameter"]
    resources = [aws_ssm_parameter.previews.arn]
  }
}

resource "aws_iam_user_policy" "cli" {
  name   = "koi-cli"
  user   = aws_iam_user.cli.name
  policy = data.aws_iam_policy_document.cli.json
}
