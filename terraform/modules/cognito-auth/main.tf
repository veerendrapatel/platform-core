# Cognito user pool for a SaaS app: email sign-in, optional authenticator-app MFA, web client (SRP + hosted-UI
# code/PKCE), an "admin" group with a bootstrap admin user, SES email, pre-sign-up trigger, optional WAF.
# The user-pool domain and social identity providers stay in the caller (they depend on app-specific secrets).
terraform {
  required_providers { aws = { source = "hashicorp/aws", version = ">= 5.70" } }
}

variable "name" {
  type        = string
  description = "Resource name prefix, e.g. reelboost-prod. Keep the existing value when adopting."
}
variable "brand" {
  type        = string
  description = "Product name shown in emails, e.g. Reel Booster."
}
variable "protect" {
  type        = bool
  description = "Deletion protection on the user pool (true for production)."
}
variable "admin_email" { type = string }
variable "admin_group_description" {
  type    = string
  default = null
}
variable "invite_email_subject" {
  type    = string
  default = null
}
variable "invite_email_message" {
  type    = string
  default = null
}
variable "invite_sms_message" {
  type    = string
  default = null
}
variable "use_ses" {
  type    = bool
  default = false
}
variable "ses_identity_arn" {
  type    = string
  default = null
}
variable "ses_domain" {
  type    = string
  default = ""
}
variable "pre_sign_up_lambda_arn" {
  type        = string
  description = "Lambda that links social and password sign-ins to one account per email."
}
variable "supported_identity_providers" {
  type    = list(string)
  default = ["COGNITO"]
}
variable "callback_urls" { type = list(string) }
variable "logout_urls" { type = list(string) }
variable "enable_auth_waf" {
  type        = bool
  default     = false
  description = "AWS WAF rate limits on the pool (about $7/month per environment)."
}

locals {
  invite_subject = coalesce(var.invite_email_subject, "Your ${var.brand} admin account")
  invite_message = coalesce(var.invite_email_message, "Welcome to ${var.brand}. Sign in with {username} and this temporary password: {####} (you'll choose a new one).")
  invite_sms     = coalesce(var.invite_sms_message, "${var.brand}: sign in with {username} and temporary password {####}")
}

resource "aws_cognito_user_pool" "main" {
  name                     = var.name
  username_attributes      = ["email"]
  auto_verified_attributes = ["email"]

  # A changed email only takes effect once the new address is verified.
  user_attribute_update_settings {
    attributes_require_verification_before_update = ["email"]
  }
  deletion_protection = var.protect ? "ACTIVE" : "INACTIVE"

  # Users can turn on authenticator-app MFA; admins should.
  mfa_configuration = "OPTIONAL"
  software_token_mfa_configuration {
    enabled = true
  }

  password_policy {
    minimum_length                   = 10
    require_lowercase                = true
    require_uppercase                = true
    require_numbers                  = true
    require_symbols                  = false
    temporary_password_validity_days = 3
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  admin_create_user_config {
    allow_admin_create_user_only = false
    invite_message_template {
      email_subject = local.invite_subject
      email_message = local.invite_message
      sms_message   = local.invite_sms
    }
  }

  # Cognito's built-in sender is limited to about 50 emails a day; SES removes that limit.
  email_configuration {
    email_sending_account = var.use_ses ? "DEVELOPER" : "COGNITO_DEFAULT"
    source_arn            = var.use_ses ? var.ses_identity_arn : null
    from_email_address    = var.use_ses ? "${var.brand} <no-reply@${var.ses_domain}>" : null
  }

  verification_message_template {
    default_email_option = "CONFIRM_WITH_CODE"
    email_subject        = "Your ${var.brand} code: {####}"
    email_message        = "Your ${var.brand} verification code is {####}. It expires in 24 hours. If you didn't sign up for ${var.brand}, you can ignore this email."
  }

  lambda_config {
    pre_sign_up = var.pre_sign_up_lambda_arn
  }

  schema {
    name                = "email"
    attribute_data_type = "String"
    required            = true
    mutable             = true
    string_attribute_constraints {
      min_length = 5
      max_length = 254
    }
  }
}

resource "aws_cognito_user_pool_client" "web" {
  name                = "${var.name}-web"
  user_pool_id        = aws_cognito_user_pool.main.id
  generate_secret     = false
  explicit_auth_flows = ["ALLOW_USER_SRP_AUTH", "ALLOW_REFRESH_TOKEN_AUTH"]

  # Hosted UI (authorization code + PKCE) for social sign-in; email/password keeps using SRP.
  supported_identity_providers         = var.supported_identity_providers
  allowed_oauth_flows_user_pool_client = true
  allowed_oauth_flows                  = ["code"]
  allowed_oauth_scopes                 = ["openid", "email", "profile"]
  callback_urls                        = var.callback_urls
  logout_urls                          = var.logout_urls
  prevent_user_existence_errors        = "ENABLED"
  enable_token_revocation              = true
  access_token_validity                = 60
  id_token_validity                    = 60
  refresh_token_validity               = 30
  token_validity_units {
    access_token  = "minutes"
    id_token      = "minutes"
    refresh_token = "days"
  }
}

resource "aws_cognito_user_group" "admin" {
  name         = "admin"
  user_pool_id = aws_cognito_user_pool.main.id
  description  = coalesce(var.admin_group_description, "${var.brand} administrators")
}

resource "aws_cognito_user" "admin" {
  user_pool_id = aws_cognito_user_pool.main.id
  username     = var.admin_email
  attributes = {
    email          = var.admin_email
    email_verified = true
  }
  desired_delivery_mediums = ["EMAIL"]
  lifecycle {
    ignore_changes = [attributes]
  }
}

resource "aws_cognito_user_in_group" "admin" {
  user_pool_id = aws_cognito_user_pool.main.id
  group_name   = aws_cognito_user_group.admin.name
  username     = aws_cognito_user.admin.sub
}

# ---- Abuse protection: AWS WAF on the user pool ----
# Cognito's own email sender allows ~50 emails a day, so a script spamming sign-ups or "resend code"
# could block real users' verification and reset emails. Per IP: at most 20 sign-up / resend /
# forgot-password calls and 300 calls of any kind per 5 minutes.

resource "aws_wafv2_web_acl" "auth" {
  count = var.enable_auth_waf ? 1 : 0
  name  = "${var.name}-auth"
  scope = "REGIONAL"

  default_action {
    allow {}
  }

  rule {
    name     = "email-sending-calls-per-ip"
    priority = 1
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit                 = 20
        evaluation_window_sec = 300
        aggregate_key_type    = "IP"
        scope_down_statement {
          or_statement {
            dynamic "statement" {
              for_each = ["SignUp", "ResendConfirmationCode", "ForgotPassword"]
              content {
                byte_match_statement {
                  search_string         = "AWSCognitoIdentityProviderService.${statement.value}"
                  positional_constraint = "EXACTLY"
                  field_to_match {
                    single_header {
                      name = "x-amz-target"
                    }
                  }
                  text_transformation {
                    priority = 0
                    type     = "NONE"
                  }
                }
              }
            }
          }
        }
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-auth-email-calls"
      sampled_requests_enabled   = true
    }
  }

  rule {
    name     = "all-calls-per-ip"
    priority = 2
    action {
      block {}
    }
    statement {
      rate_based_statement {
        limit                 = 300
        evaluation_window_sec = 300
        aggregate_key_type    = "IP"
      }
    }
    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "${var.name}-auth-all-calls"
      sampled_requests_enabled   = true
    }
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.name}-auth"
    sampled_requests_enabled   = true
  }
}

resource "aws_wafv2_web_acl_association" "auth" {
  count        = var.enable_auth_waf ? 1 : 0
  resource_arn = aws_cognito_user_pool.main.arn
  web_acl_arn  = aws_wafv2_web_acl.auth[0].arn
}

output "user_pool_id" { value = aws_cognito_user_pool.main.id }
output "user_pool_arn" { value = aws_cognito_user_pool.main.arn }
output "client_id" { value = aws_cognito_user_pool_client.web.id }
