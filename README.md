# platform-core

Shared building blocks for the SaaS products (Reel Booster, DocOps, ...), extracted from their near-identical copies.

## Terraform modules (`terraform/modules/`)
| Module | What | Replaces |
|---|---|---|
| `ses-email` | SES domain identity, MAIL FROM, suppression list, bounce/complaint alerts | `ses.tf` (identical in both products) |
| `cognito-auth` | user pool, web client, admin group + user, SES email, pre-sign-up trigger, optional WAF | `cognito.tf` (differs only in brand text and the protect flag) |

Not in the modules by design: the user-pool domain and Google/Facebook providers (`social.tf`), which hold app-specific secrets.

## Adopting in a product
1. Call the modules from the product's `infra/` and add `moved` blocks (resource -> `module.<name>.<resource>`) so state is re-addressed, not recreated.
2. Update references (`aws_cognito_user_pool.main.id` -> `module.auth.user_pool_id`, DKIM tokens -> `module.ses.dkim_tokens`).
3. `terraform plan` per environment. Expect only moves; any create/destroy of a user pool or SES identity means stop.
