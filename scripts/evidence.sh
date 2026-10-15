#!/usr/bin/env bash
# Prints a QSA-style evidence summary of the deployed FinGuard PoC (read-only).
export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-eu-central-1}
P=finguard
q () { aws "$@" 2>/dev/null; }
hr () { printf '\n== %s\n' "$1"; }

hr "CloudFormation stacks"
q cloudformation describe-stacks --query "Stacks[?starts_with(StackName,'$P')].[StackName,StackStatus]" --output text

hr "Network (PCI DSS 1.2-1.4)"
VPC=$(q ec2 describe-vpcs --filters Name=tag:Name,Values=$P-vpc --query 'Vpcs[0].VpcId' --output text)
q ec2 describe-subnets --filters Name=vpc-id,Values=$VPC --query 'sort_by(Subnets,&CidrBlock)[].[Tags[?Key==`Name`]|[0].Value,CidrBlock,AvailabilityZone,MapPublicIpOnLaunch]' --output text
for rt in app data-isolated; do
  printf "%-22s default route: " "rt-$rt"
  q ec2 describe-route-tables --filters Name=tag:Name,Values=$P-rt-$rt --query "RouteTables[0].Routes[?DestinationCidrBlock=='0.0.0.0/0'] | length(@)" --output text | sed 's/^0$/none (no internet path)/'
done
q ec2 describe-vpc-endpoints --filters Name=vpc-id,Values=$VPC --query 'VpcEndpoints[].[ServiceName,VpcEndpointType,State]' --output text
q ec2 describe-vpn-connections --filters Name=tag:Name,Values=$P-vpn-partner-bank --query 'VpnConnections[0].[VpnConnectionId,State,length(VgwTelemetry)]' --output text | awk '{print "site-to-site VPN", $1, $2, $3" tunnels"}'
q route53resolver list-firewall-rule-group-associations --vpc-id $VPC --query 'FirewallRuleGroupAssociations[].[Name,Status]' --output text | sed 's/^/DNS Firewall /'
q ec2 describe-flow-logs --filter Name=resource-id,Values=$VPC --query 'FlowLogs[].[FlowLogStatus,TrafficType,LogDestinationType]' --output text | sed 's/^/VPC Flow Logs /'

hr "Keys and encryption (PCI DSS 3.5-3.7)"
for a in cde-data pan-token audit-logs; do
  K=$(q kms describe-key --key-id alias/$P-$a --query 'KeyMetadata.[KeyId,KeySpec,KeyState]' --output text)
  R=$(q kms get-key-rotation-status --key-id $(echo $K | cut -d" " -f1) --query '[KeyRotationEnabled,RotationPeriodInDays]' --output text)
  printf "%-22s %s rotation=%s\n" "alias/$P-$a" "$K" "${R:-n/a (HMAC)}"
done
q dynamodb describe-table --table-name $P-transactions --query 'Table.[TableName,SSEDescription.SSEType,SSEDescription.Status,BillingModeSummary.BillingMode]' --output text
q dynamodb describe-continuous-backups --table-name $P-transactions --query 'ContinuousBackupsDescription.PointInTimeRecoveryDescription.[PointInTimeRecoveryStatus,RecoveryPeriodInDays]' --output text | sed 's/^/PITR /'

hr "Identity (PCI DSS 7, 8)"
POOL=$(q cognito-idp list-user-pools --max-results 20 --query "UserPools[?Name=='$P-customers'].Id | [0]" --output text)
q cognito-idp get-user-pool-mfa-config --user-pool-id $POOL --query '[MfaConfiguration,SoftwareTokenMfaConfiguration.Enabled]' --output text | sed 's/^/Cognito MFA /'
for r in platform-admin qsa-auditor; do
  printf "%-22s MFA required to assume: " "role/$P-$r"
  q iam get-role --role-name $P-$r --query 'Role.AssumeRolePolicyDocument.Statement[0].Condition.Bool."aws:MultiFactorAuthPresent"' --output text
done
q iam get-role --role-name $P-txn-lambda --query 'Role.PermissionsBoundary.PermissionsBoundaryArn' --output text | sed 's/^/Lambda permission boundary /'

hr "Edge protection (PCI DSS 6.4)"
q wafv2 list-web-acls --scope REGIONAL --query "WebACLs[?Name=='$P-api-waf'].Name" --output text | sed 's/^/WAF web ACL /'
ACL=$(q wafv2 list-web-acls --scope REGIONAL --query "WebACLs[?Name=='$P-api-waf'] | [0].[Name,Id]" --output text)
q wafv2 get-web-acl --scope REGIONAL --name $(echo $ACL | cut -d' ' -f1) --id $(echo $ACL | cut -d' ' -f2) --query 'WebACL.Rules[].[Priority,Name]' --output text

hr "Audit and detection (PCI DSS 10, 11)"
q cloudtrail get-trail --name $P-audit-trail --query 'Trail.[Name,IsMultiRegionTrail,LogFileValidationEnabled,KmsKeyId!=`null`]' --output text | awk '{print $1, "multiRegion="$2, "logFileValidation="$3, "kmsEncrypted="$4}'
q cloudtrail get-trail-status --name $P-audit-trail --query 'IsLogging' --output text | sed 's/^/trail logging=/'
q cloudwatch describe-alarms --alarm-name-prefix $P- --query 'MetricAlarms[].[AlarmName,StateValue]' --output text
q configservice describe-compliance-by-config-rule --query "ComplianceByConfigRules[?starts_with(ConfigRuleName,'$P')].[ConfigRuleName,Compliance.ComplianceType]" --output text
q budgets describe-budget --account-id $(q sts get-caller-identity --query Account --output text) --budget-name $P-poc-1usd --query 'Budget.[BudgetName,BudgetLimit.Amount,CalculatedSpend.ActualSpend.Amount]' --output text | sed 's/^/Budget /'
