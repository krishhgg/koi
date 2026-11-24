# ---------------------------------------------------------------------------
# The wake function: serves the "waking up" page and starts the box when a
# known preview is requested. Reached only through CloudFront.
# ---------------------------------------------------------------------------

# scripts/build-lambda.sh writes files/handler.mjs from packages/lambda; it is
# not committed. A copy of the module for another repository carries the
# built file.
data "archive_file" "wake" {
  type        = "zip"
  source_file = "${path.module}/files/handler.mjs"
  output_path = "${path.module}/files/wake.zip"
}

resource "aws_cloudwatch_log_group" "wake" {
  #checkov:skip=CKV_AWS_158:The wake function logs only its own errors from the EC2 and SSM calls; the encryption CloudWatch applies by default is enough for those.
  #checkov:skip=CKV_AWS_338:Two weeks of wake logs is enough to debug a wake page; nothing audits them.
  name              = "/aws/lambda/${local.wake_name}"
  retention_in_days = 14
  tags              = var.tags
}

data "aws_iam_policy_document" "wake_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "wake" {
  name               = local.wake_name
  assume_role_policy = data.aws_iam_policy_document.wake_assume.json
  tags               = var.tags
}

data "aws_iam_policy_document" "wake" {
  statement {
    sid       = "Logs"
    actions   = ["logs:CreateLogStream", "logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.wake.arn}:*"]
  }
  statement {
    sid       = "StartBox"
    actions   = ["ec2:StartInstances"]
    resources = [aws_instance.box.arn]
  }
  # DescribeInstances has no resource-level scoping in IAM.
  statement {
    sid       = "DescribeBox"
    actions   = ["ec2:DescribeInstances"]
    resources = ["*"]
  }
  statement {
    sid       = "PreviewList"
    actions   = ["ssm:GetParameter"]
    resources = [aws_ssm_parameter.previews.arn]
  }
}

resource "aws_iam_role_policy" "wake" {
  name   = local.wake_name
  role   = aws_iam_role.wake.id
  policy = data.aws_iam_policy_document.wake.json
}

resource "aws_lambda_function" "wake" {
  #checkov:skip=CKV_AWS_116:CloudFront calls the function synchronously through its URL; there is no asynchronous event to send to a dead-letter queue.
  #checkov:skip=CKV_AWS_117:It calls only the EC2 and SSM APIs and needs nothing inside a VPC; in one it would need a NAT gateway or endpoints to reach them.
  #checkov:skip=CKV_AWS_173:The environment holds the instance ID, the parameter name and the domain, none of them secret.
  #checkov:skip=CKV_AWS_272:The code comes from this repository's build in the same apply; there is no separate publisher to verify.
  #checkov:skip=CKV_AWS_50:X-Ray would trace two API calls per request; the log group is enough.
  function_name    = local.wake_name
  role             = aws_iam_role.wake.arn
  runtime          = "nodejs22.x"
  architectures    = ["arm64"]
  handler          = "handler.handler"
  filename         = data.archive_file.wake.output_path
  source_code_hash = data.archive_file.wake.output_base64sha256
  timeout          = 10
  memory_size      = 256
  tags             = var.tags

  # Also a cap on what a flood of requests for unknown previews can cost.
  reserved_concurrent_executions = var.wake_reserved_concurrency

  environment {
    variables = {
      KOI_INSTANCE_ID    = aws_instance.box.id
      KOI_PREVIEWS_PARAM = aws_ssm_parameter.previews.name
      KOI_DOMAIN         = var.domain
    }
  }

  depends_on = [aws_cloudwatch_log_group.wake, aws_iam_role_policy.wake]
}

resource "aws_lambda_function_url" "wake" {
  function_name      = aws_lambda_function.wake.function_name
  authorization_type = "AWS_IAM"
}

# Function URLs created since late 2025 need both permissions for an IAM-auth
# caller: InvokeFunctionUrl for the URL and InvokeFunction for the function.
resource "aws_lambda_permission" "wake_url_from_cloudfront" {
  statement_id           = "AllowCloudFrontInvokeUrl"
  action                 = "lambda:InvokeFunctionUrl"
  function_name          = aws_lambda_function.wake.function_name
  principal              = "cloudfront.amazonaws.com"
  source_arn             = aws_cloudfront_distribution.edge.arn
  function_url_auth_type = "AWS_IAM"
}

resource "aws_lambda_permission" "wake_from_cloudfront" {
  statement_id  = "AllowCloudFrontInvokeFunction"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.wake.function_name
  principal     = "cloudfront.amazonaws.com"
  source_arn    = aws_cloudfront_distribution.edge.arn
}
