#!/usr/bin/env bash
# Disaster-recovery drill: simulate an operator error, then recover the table with
# point-in-time recovery (PITR) and an AWS Backup recovery point. Measures RPO/RTO.
set -euo pipefail
export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-eu-central-1}
T=finguard-transactions
R=finguard-transactions-restored-$(date +%H%M)

echo "== on-demand AWS Backup job (evidence for the vault)"
ARN=$(aws dynamodb describe-table --table-name $T --query Table.TableArn --output text)
ROLE=$(aws iam list-roles --query "Roles[?contains(RoleName,'finguard-app-BackupRole')].Arn | [0]" --output text)
aws backup start-backup-job --backup-vault-name finguard-vault --resource-arn "$ARN" --iam-role-arn "$ROLE" \
  --lifecycle DeleteAfterDays=1 --query BackupJobId --output text

echo "== PITR status"
aws dynamodb describe-continuous-backups --table-name $T \
  --query 'ContinuousBackupsDescription.PointInTimeRecoveryDescription' --output table

BEFORE=$(aws dynamodb scan --table-name $T --select COUNT --query Count --output text)
STAMP=$(date -u +%s)
echo "items before incident: $BEFORE   (restore point = $(date -u -d @$STAMP +%FT%TZ))"
sleep 5

echo "== simulated incident: an operator deletes 5 transaction items"
aws dynamodb scan --table-name $T --max-items 5 --projection-expression "pk,sk" --output json \
 | python3 -c "import json,sys,subprocess
for i in json.load(sys.stdin)['Items']:
    subprocess.run(['aws','dynamodb','delete-item','--table-name','$T','--key',json.dumps({'pk':i['pk'],'sk':i['sk']})],check=True)"
AFTER=$(aws dynamodb scan --table-name $T --select COUNT --query Count --output text)
echo "items after incident:  $AFTER"

echo "== restore to the point just before the incident"
T0=$(date +%s)
aws dynamodb restore-table-to-point-in-time --source-table-name $T --target-table-name $R \
  --restore-date-time $STAMP --sse-specification-override "Enabled=true,SSEType=KMS,KMSMasterKeyId=alias/finguard-cde-data" >/dev/null
aws dynamodb wait table-exists --table-name $R
until [ "$(aws dynamodb describe-table --table-name $R --query Table.TableStatus --output text)" = "ACTIVE" ]; do sleep 10; done
T1=$(date +%s)
aws dynamodb update-continuous-backups --table-name $R --point-in-time-recovery-specification PointInTimeRecoveryEnabled=true >/dev/null  # restores do not inherit PITR
RESTORED=$(aws dynamodb scan --table-name $R --select COUNT --query Count --output text)
echo "restored table $R ACTIVE with $RESTORED items; RTO(restore)=$(( (T1-T0)/60 )) min $(( (T1-T0)%60 )) s"
echo "RPO: restore point was taken $(( T0-STAMP )) s before the restore started (PITR granularity is seconds)"
