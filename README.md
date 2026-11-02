# FinGuard PCI PoC – Compliance as Code on AWS

A proof of concept for a secured, audited payment-instruction platform for the fictitious payment
start-up *FinGuard*. It is aligned with PCI DSS v4.0.1 and the EU Digital Operational Resilience Act
(DORA) and is deployed entirely as code in `eu-central-1` (Frankfurt).

Author: Manas Ranjan Rao ([@LLawliet188](https://github.com/LLawliet188))

## What it shows

- **No card number at rest:** the PAN is replaced by a keyed hash computed inside AWS KMS; only the token and masked digits are stored.
- **Isolated workload:** a three-tier VPC across two Availability Zones, no internet route for the application and data tiers, VPC endpoints instead of a NAT gateway, and a DNS Firewall allow-list.
- **Identity:** Cognito with mandatory TOTP multi-factor authentication for customers, and MFA-gated IAM roles with a permission boundary for staff.
- **Audit and detection:** a multi-Region CloudTrail trail with data events and log-file validation, CIS-based metric-filter alarms, AWS Config rules and VPC Flow Logs.
- **Compliance as code:** cfn-lint, Checkov, CloudFormation Guard rules mapped to PCI DSS, and unit tests as gates in a GitHub Actions pipeline using OIDC.
- **Recovery:** DynamoDB point-in-time recovery and AWS Backup, with a scripted disaster-recovery drill.

## Repository layout

| Path | Purpose |
|---|---|
| `templates/00-security.yaml` | KMS keys (data, HMAC token, logs), CloudTrail with Object Lock, CIS alarms, GuardDuty (conditional), AWS Config rules, MFA-gated roles, permission boundary, cost budget |
| `templates/01-network.yaml` | Three-tier VPC, NACLs and security groups, gateway and KMS endpoints, DNS Firewall, Flow Logs, site-to-site VPN |
| `templates/02-app.yaml` | Cognito, AWS WAF, API Gateway, Lambda in the VPC, DynamoDB (CMK, PITR), S3, AWS Backup, dashboard, alarms |
| `src/transactions/app.py` | Transaction handler: Luhn/IBAN validation, KMS HMAC tokenisation, idempotency, tenant isolation |
| `policy/finguard-pci.guard` | PCI DSS rules as CloudFormation Guard policy-as-code |
| `tests/` | Unit tests (moto) and a deliberately non-compliant template for a negative Guard test |
| `scripts/` | Deploy, end-to-end test, load test, DR drill, evidence summary, teardown |
| `.github/workflows/iac-pipeline.yml` | Four gates on every pull request; OIDC deployment through a protected environment |
| `docs/c4-network.dot` | Source of the C4 network diagram |

## Pipeline gates

```
cfn-lint templates/*.yaml --ignore-checks W3002
checkov -d templates --framework cloudformation
cfn-guard validate -d templates -r policy/finguard-pci.guard
python -m pytest -q tests
```

## Run it (AWS CloudShell, eu-central-1)

```
./scripts/deploy.sh                 # three stacks, about 12 minutes on the first run
python3 scripts/e2e_test.py         # functional and security checks against the live API
cd scripts && python3 load_test.py  # steady load, surge and AWS WAF flood
./scripts/dr_drill.sh               # point-in-time restore drill
./scripts/evidence.sh               # read-only evidence summary
./scripts/teardown.sh               # removes every billable resource
```

The site-to-site VPN and the KMS interface endpoint are billed per hour, so run `teardown.sh` after testing.
An AWS Budget alarm is part of the security stack.

## Results of the first run (October 2026)

- All 12 end-to-end checks passed: MFA sign-in, authorisation, schema validation, tenant isolation, AWS WAF blocking and no PAN at rest.
- The restored table contained every item that existed before the simulated operator error.
- Under a surge, the account's default Lambda concurrency limit caused server errors. Aligning the API throttle with that limit turned most of them into retryable `429` responses, but did not add capacity.

## Known limitations and v2 roadmap

Version 1 is a proof of concept. A review identified the following points, which version 2 addresses:

- **Recovery metrics:** measure data loss and recovery time end to end, including switching the application to the restored table.
- **Latency:** report latency percentiles together with error rates, not over successful requests only.
- **Scaling:** size throttling from concurrency (request rate × duration) rather than request rate alone.
- **Policy-as-code:** make Guard rules fail when they do not match the expected resources, and stop relying on tags to select them.
- **Tokenisation:** replace keyed-hash tokens with random tokens held in a separate vault, because truncated digits narrow the search space for anyone allowed to verify tokens.
- **Idempotency:** reject a reused idempotency key that arrives with a different request body.
- **Further work:** multi-account setup with AWS Organizations, a warm standby in a second EU Region, and enabling GuardDuty.
