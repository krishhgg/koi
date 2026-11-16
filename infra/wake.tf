# ---------------------------------------------------------------------------
# The wake function: serves the "waking up" page and starts the box when a
# known preview is requested. Reached only through CloudFront.
# ---------------------------------------------------------------------------

data "archive_file" "wake" {
  type        = "zip"
  source_file = "${path.module}/../packages/lambda/dist/handler.mjs"
  output_path = "${path.module}/../packages/lambda/dist/wake.zip"
}

resource "aws_cloudwatch_log_group" "wake" {
  name              = "/aws/lambda/koi-wake"
  retention_in_days = 14
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
  name               = "koi-wake"
  assume_role_policy = data.aws_iam_policy_document.wake_assume.json
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
  name   = "koi-wake"
  role   = aws_iam_role.wake.id
  policy = data.aws_iam_policy_document.wake.json
}

resource "aws_lambda_function" "wake" {
  function_name    = "koi-wake"
  role             = aws_iam_role.wake.arn
  runtime          = "nodejs22.x"
  architectures    = ["arm64"]
  handler          = "handler.handler"
  filename         = data.archive_file.wake.output_path
  source_code_hash = data.archive_file.wake.output_base64sha256
  timeout          = 10
  memory_size      = 256

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
