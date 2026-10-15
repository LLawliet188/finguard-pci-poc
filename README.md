# FinGuard PCI PoC – Compliance as Code on AWS

Proof of concept for **DLBPAWSCLAD – Project AWS: Cloud Advanced (Task 2)**, IU International University of Applied Sciences.
Author: Manas Ranjan Rao (matriculation number 92017693) · Tutor: Prof. Dr. Tianxiang Lu

A secured, audited payment-instruction platform for the fictitious payment start-up *FinGuard*, aligned with
PCI DSS v4.0.1 and DORA and deployed entirely as code in `eu-central-1` (Frankfurt).

## Repository layout

| Path | Purpose |
|---|---|
| `templates/00-security.yaml` | KMS keys (data, HMAC token, logs), CloudTrail + Object Lock, CIS alarms, GuardDuty (conditional), AWS Config rules, MFA-gated roles, permission boundary, USD 1 budget |
| `templates/01-network.yaml` | Three-tier VPC across two AZs, NACLs and security groups, gateway and KMS endpoints, DNS Firewall, Flow Logs, site-to-site VPN |
| `templates/02-app.yaml` | Cognito (MFA required), AWS WAF, API Gateway, Lambda in the VPC, DynamoDB (CMK, PITR), S3, AWS Backup, dashboard, alarms |
| `src/transactions/app.py` | Transaction handler: Luhn/IBAN validation, KMS HMAC tokenisation of the PAN, idempotency, tenant isolation |
| `policy/finguard-pci.guard` | Eight PCI DSS rules as CloudFormation Guard policy-as-code |
| `tests/` | Unit tests (moto) and a deliberately non-compliant template for the negative Guard test |
| `scripts/` | Deploy, end-to-end test, load test, DR drill, evidence summary, teardown |
| `.github/workflows/iac-pipeline.yml` | Four gates on every pull request; OIDC deployment through a protected environment |
| `docs/c4-network.dot` | Source of the C4 network diagram |

## Pipeline gates

```
cfn-lint templates/*.yaml --ignore-checks W3002
checkov -d templates --framework cloudformation        # 135 passed, 0 failed, 10 justified skips
cfn-guard validate -d templates -r policy/finguard-pci.guard
python -m pytest -q tests                              # 10 passed
```

## Run it (AWS CloudShell, eu-central-1)

```
./scripts/deploy.sh                 # three stacks, ~12 min on first run
python3 scripts/e2e_test.py         # 12 functional and security checks
cd scripts && python3 load_test.py  # steady load, surge and WAF flood
./scripts/dr_drill.sh               # PITR restore with measured RTO
./scripts/evidence.sh               # read-only QSA-style evidence summary
./scripts/teardown.sh               # removes every billable resource
```

The site-to-site VPN and the KMS interface endpoint are billed per hour; run `teardown.sh` after testing.

## Measured results (14 October 2026)

| KPI | Target | Result |
|---|---|---|
| p95 latency, steady load | < 500 ms | 171 ms |
| Security tests | 12 / 12 | 12 / 12 passed |
| PAN stored in clear text | 0 | 0 |
| Recovery time (PITR restore) | < 60 min | 3 min 43 s, no committed transaction lost |
| Surge without server errors | 0 | not met – 258 → 17 after aligning the throttle with the account's Lambda concurrency quota |
| Demonstration cost | ≤ USD 1 | < USD 0.80 (estimate) |

The full analysis, reflection and recommendations are in the project report submitted to IU.
