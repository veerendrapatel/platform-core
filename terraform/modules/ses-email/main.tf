# SES sending identity for Cognito (and app) email: domain identity, custom MAIL FROM, suppression list,
# and bounce/complaint notifications to an alerts SNS topic. Does nothing while ses_domain is "".
#
# Two-step rollout: set ses_domain and apply, add the DKIM CNAMEs (dkim_tokens), then once SES shows the
# domain as verified switch Cognito to it (cognito-auth use_ses). New SES accounts start in the sandbox;
# request production access in the SES console before launch.
#
# The caller must make sure the alerts topic policy allows SES to publish, e.g.
#   module "ses" { ...; depends_on = [aws_sns_topic_policy.alerts] }
terraform {
  required_providers { aws = { source = "hashicorp/aws", version = ">= 5.70" } }
}

variable "ses_domain" {
  type    = string
  default = ""
}
variable "alerts_topic_arn" {
  type        = string
  description = "SNS topic that receives bounce and complaint notifications."
}

locals { enabled = var.ses_domain != "" }

resource "aws_sesv2_email_identity" "domain" {
  count          = local.enabled ? 1 : 0
  email_identity = var.ses_domain
}

resource "aws_sesv2_email_identity_mail_from_attributes" "domain" {
  count                  = local.enabled ? 1 : 0
  email_identity         = aws_sesv2_email_identity.domain[0].email_identity
  mail_from_domain       = "mail.${var.ses_domain}"
  behavior_on_mx_failure = "USE_DEFAULT_VALUE"
}

# Never email an address again after it hard-bounces or its owner marks us as spam.
resource "aws_sesv2_account_suppression_attributes" "main" {
  count              = local.enabled ? 1 : 0
  suppressed_reasons = ["BOUNCE", "COMPLAINT"]
}

resource "aws_ses_identity_notification_topic" "feedback" {
  for_each                 = local.enabled ? toset(["Bounce", "Complaint"]) : toset([])
  identity                 = aws_sesv2_email_identity.domain[0].email_identity
  notification_type        = each.key
  topic_arn                = var.alerts_topic_arn
  include_original_headers = false
}

output "identity_arn" {
  value       = local.enabled ? aws_sesv2_email_identity.domain[0].arn : null
  description = "ARN of the domain identity, or null when ses_domain is empty."
}
output "dkim_tokens" {
  value       = local.enabled ? aws_sesv2_email_identity.domain[0].dkim_signing_attributes[0].tokens : []
  description = "DKIM tokens; publish each as <token>._domainkey.<domain> CNAME <token>.dkim.amazonses.com."
}
