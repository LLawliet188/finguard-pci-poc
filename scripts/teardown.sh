#!/usr/bin/env bash
# Removes every billable FinGuard resource. KMS keys enter a 7-day pending-deletion
# window (no charge while pending). Run, then confirm with: aws resourcegroupstaggingapi get-resources --tag-filters Key=project,Values=finguard
set -uo pipefail
cd "$(dirname "$0")/.."
export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-eu-central-1}
P=finguard
ACCT=$(aws sts get-caller-identity --query Account --output text)

empty_bucket () {   # removes all versions, bypassing GOVERNANCE object-lock retention
python3 - "$1" <<'EOF'
import sys, boto3
s3 = boto3.client("s3"); b = boto3.resource("s3").Bucket(sys.argv[1])
try:
    try:   # the bypass header is only accepted on Object Lock buckets
        locked = s3.get_object_lock_configuration(Bucket=sys.argv[1])["ObjectLockConfiguration"]["ObjectLockEnabled"] == "Enabled"
    except s3.exceptions.ClientError:
        locked = False
    for page in b.object_versions.pages():
        objs = [{"Key": v.object_key, "VersionId": v.id} for v in page]
        if objs:
            b.delete_objects(Delete={"Objects": objs}, **({"BypassGovernanceRetention": True} if locked else {}))
    print("emptied", sys.argv[1])
except Exception as e:
    print("skip", sys.argv[1], e)
EOF
}

# restored DR tables
for t in $(aws dynamodb list-tables --query "TableNames[?starts_with(@,'$P-transactions-restored')]" --output text); do
  aws dynamodb delete-table --table-name "$t" >/dev/null && echo "deleted $t"; done

# recovery points in the vault (vault cannot be deleted while it holds any)
for rp in $(aws backup list-recovery-points-by-backup-vault --backup-vault-name $P-vault --query 'RecoveryPoints[].RecoveryPointArn' --output text 2>/dev/null); do
  aws backup delete-recovery-point --backup-vault-name $P-vault --recovery-point-arn "$rp" && echo "deleted recovery point"; done

empty_bucket $P-settlement-$ACCT-$AWS_DEFAULT_REGION
aws cloudformation delete-stack --stack-name $P-app && aws cloudformation wait stack-delete-complete --stack-name $P-app && echo "app stack deleted"
aws cloudformation delete-stack --stack-name $P-network && aws cloudformation wait stack-delete-complete --stack-name $P-network && echo "network stack deleted"
aws cloudtrail stop-logging --name $P-audit-trail 2>/dev/null
aws configservice stop-configuration-recorder --configuration-recorder-name $P-recorder 2>/dev/null
aws cloudformation deploy --stack-name $P-security --template-file templates/00-security.yaml --capabilities CAPABILITY_NAMED_IAM --no-fail-on-empty-changeset --parameter-overrides EnableConfig=false EnableGuardDuty=false >/dev/null 2>&1
aws configservice delete-delivery-channel --delivery-channel-name $P-delivery 2>/dev/null
aws configservice delete-configuration-recorder --configuration-recorder-name $P-recorder 2>/dev/null && echo "config recorder deleted"
sleep 20
empty_bucket $P-audit-$ACCT-$AWS_DEFAULT_REGION
empty_bucket $P-config-$ACCT-$AWS_DEFAULT_REGION
aws cloudformation delete-stack --stack-name $P-security && aws cloudformation wait stack-delete-complete --stack-name $P-security && echo "security stack deleted"
empty_bucket $P-artifacts-$ACCT-$AWS_DEFAULT_REGION
aws s3api delete-bucket --bucket $P-artifacts-$ACCT-$AWS_DEFAULT_REGION 2>/dev/null && echo "artifact bucket deleted"

echo "== KMS keys now pending deletion (free while pending):"
aws kms list-aliases --query "Aliases[?starts_with(AliasName,'alias/$P')].AliasName" --output text
echo "== remaining tagged resources:"
aws resourcegroupstaggingapi get-resources --tag-filters Key=project,Values=$P --query 'ResourceTagMappingList[].ResourceARN' --output text
