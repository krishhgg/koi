# ---------------------------------------------------------------------------
# What `koi up` needs and nothing else, as a policy document (output
# operator_policy_json). The personal root attaches it to the koi-cli IAM
# user; elsewhere it is the inline policy of an Identity Center permission
# set or a role.
#
# ssm:SendCommand with AWS-RunShellScript on the box is root on the box
# (README, "Trust model and limits"). Running scripts/deploy-host.sh or
# scripts/provision-host.sh needs more than this: s3:GetObject under host/
# for the presigned downloads, and the operator's admin session for
# anything else.
# ---------------------------------------------------------------------------

data "aws_iam_policy_document" "operator" {
  statement {
    sid       = "UploadSource"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.uploads.arn}/*"]
  }
  # An AWS-owned document's ARN has no account.
  statement {
    sid     = "RunOnBox"
    actions = ["ssm:SendCommand"]
    resources = [
      aws_instance.box.arn,
      "arn:${local.partition}:ssm:${local.region}::document/AWS-RunShellScript",
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
