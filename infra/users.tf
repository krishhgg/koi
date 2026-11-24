# ---------------------------------------------------------------------------
# koi-cli: what `koi up` needs and nothing else, from the module's operator
# policy. Its access key is created by infra/bootstrap.sh, outside the state
# file. Only the personal root has it; an account with Identity Center gives
# people a permission set with the same policy instead.
#
# There is deliberately no deploy user. Any policy broad enough to run
# `tofu apply` (create roles, attach policies) is broad enough to grant itself
# administrator, so a scoped deploy user protects nothing. Infrastructure is
# applied with the operator's own short-lived admin session (`aws login`).
# ---------------------------------------------------------------------------

resource "aws_iam_user" "cli" {
  #checkov:skip=CKV_AWS_273:The personal account has no Identity Center, and `koi up` runs unattended from agents that cannot renew an SSO session. Company roots use the module's operator_policy_json in a permission set instead.
  name = "koi-cli"
}

resource "aws_iam_user_policy" "cli" {
  #checkov:skip=CKV_AWS_40:One user with one narrow policy; a group would add a resource and change nothing it may do.
  name   = "koi-cli"
  user   = aws_iam_user.cli.name
  policy = module.koi.operator_policy_json
}
