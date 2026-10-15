#!/usr/bin/env bash
# One-command deployment of the FinGuard PCI PoC (designed for AWS CloudShell).
# Usage: ./scripts/deploy.sh [alert-email]
set -euo pipefail
cd "$(dirname "$0")/.."
export AWS_DEFAULT_REGION=${AWS_DEFAULT_REGION:-eu-central-1}
P=finguard
ACCT=$(aws sts get-caller-identity --query Account --output text)
EMAIL=${1:-""}

# Reuse existing account-level singletons instead of failing on them
GD=$(aws guardduty list-detectors --query 'length(DetectorIds)' --output text 2>/dev/null || echo unavailable)
[ "$GD" = "0" ] && ENABLE_GD=true || ENABLE_GD=false
CFG=$(aws configservice describe-configuration-recorders --query "length(ConfigurationRecorders[?name!='$P-recorder'])" --output text)
[ "$CFG" = "0" ] && ENABLE_CFG=true || ENABLE_CFG=false   # a foreign recorder means: reuse it, skip ours
CONC=$(aws lambda get-account-settings --query 'AccountLimit.ConcurrentExecutions' --output text)
[ "$CONC" -ge 100 ] && RESERVED=20 || RESERVED=0
echo "account=$ACCT guardduty=$ENABLE_GD config=$ENABLE_CFG lambda-quota=$CONC reserved=$RESERVED"

echo "== 1/3 security & audit baseline"
time aws cloudformation deploy --stack-name $P-security --template-file templates/00-security.yaml \
  --capabilities CAPABILITY_NAMED_IAM --no-fail-on-empty-changeset \
  --parameter-overrides AlertEmail="$EMAIL" EnableGuardDuty=$ENABLE_GD EnableConfig=false \
  --tags project=$P pci-scope=cde

out () { aws cloudformation describe-stacks --stack-name $P-security --query "Stacks[0].Outputs[?OutputKey=='$1'].OutputValue" --output text; }
if [ "$ENABLE_CFG" = "true" ]; then
  echo "== AWS Config recorder (recorder -> delivery channel -> start)"
  aws configservice put-configuration-recorder --configuration-recorder "{\"name\":\"$P-recorder\",\"roleARN\":\"$(out ConfigRoleArn)\",\"recordingGroup\":{\"allSupported\":false,\"includeGlobalResourceTypes\":false,\"resourceTypes\":[\"AWS::DynamoDB::Table\",\"AWS::S3::Bucket\",\"AWS::EC2::SecurityGroup\",\"AWS::EC2::VPC\",\"AWS::EC2::Subnet\",\"AWS::EC2::NetworkAcl\",\"AWS::KMS::Key\",\"AWS::CloudTrail::Trail\",\"AWS::Lambda::Function\",\"AWS::ApiGateway::Stage\"]},\"recordingMode\":{\"recordingFrequency\":\"DAILY\"}}"
  aws configservice put-delivery-channel --delivery-channel name=$P-delivery,s3BucketName=$(out ConfigBucketName),s3KeyPrefix=config,s3KmsKeyArn=$(out LogKeyArn)
  aws configservice start-configuration-recorder --configuration-recorder-name $P-recorder
  aws cloudformation deploy --stack-name $P-security --template-file templates/00-security.yaml \
    --capabilities CAPABILITY_NAMED_IAM --no-fail-on-empty-changeset \
    --parameter-overrides AlertEmail="$EMAIL" EnableGuardDuty=$ENABLE_GD EnableConfig=true --tags project=$P pci-scope=cde
fi

LOGKEY=$(aws cloudformation describe-stacks --stack-name $P-security --query "Stacks[0].Outputs[?OutputKey=='LogKeyArn'].OutputValue" --output text)

echo "== 2/3 network"
PL () { aws ec2 describe-managed-prefix-lists --filters Name=prefix-list-name,Values=com.amazonaws.$AWS_DEFAULT_REGION.$1 --query 'PrefixLists[0].PrefixListId' --output text; }
time aws cloudformation deploy --stack-name $P-network --template-file templates/01-network.yaml \
  --capabilities CAPABILITY_IAM --no-fail-on-empty-changeset \
  --parameter-overrides LogKeyArn="$LOGKEY" DynamoPrefixListId=$(PL dynamodb) S3PrefixListId=$(PL s3) --tags project=$P pci-scope=cde

echo "== close the VPC default security group (PCI DSS 1.2.1 / CIS 5.5)"
VPC=$(aws ec2 describe-vpcs --filters Name=tag:Name,Values=$P-vpc --query 'Vpcs[0].VpcId' --output text)
DSG=$(aws ec2 describe-security-groups --filters Name=vpc-id,Values=$VPC Name=group-name,Values=default --query 'SecurityGroups[0].GroupId' --output text)
IN=$(aws ec2 describe-security-groups --group-ids $DSG --query 'SecurityGroups[0].IpPermissions' --output json)
OUT=$(aws ec2 describe-security-groups --group-ids $DSG --query 'SecurityGroups[0].IpPermissionsEgress' --output json)
[ "$IN" != "[]" ] && aws ec2 revoke-security-group-ingress --group-id $DSG --ip-permissions "$IN" >/dev/null
[ "$OUT" != "[]" ] && aws ec2 revoke-security-group-egress --group-id $DSG --ip-permissions "$OUT" >/dev/null

echo "== 3/3 application"
ART=$P-artifacts-$ACCT-$AWS_DEFAULT_REGION
aws s3api head-bucket --bucket "$ART" 2>/dev/null || {
  aws s3api create-bucket --bucket "$ART" --create-bucket-configuration LocationConstraint=$AWS_DEFAULT_REGION >/dev/null
  aws s3api put-public-access-block --bucket "$ART" --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
  aws s3api put-bucket-policy --bucket "$ART" --policy "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Sid\":\"DenyNonTls\",\"Effect\":\"Deny\",\"Principal\":\"*\",\"Action\":\"s3:*\",\"Resource\":[\"arn:aws:s3:::$ART\",\"arn:aws:s3:::$ART/*\"],\"Condition\":{\"Bool\":{\"aws:SecureTransport\":\"false\"}}}]}"; }
aws cloudformation package --template-file templates/02-app.yaml --s3-bucket "$ART" --output-template-file /tmp/02-app.packaged.yaml >/dev/null
time aws cloudformation deploy --stack-name $P-app --template-file /tmp/02-app.packaged.yaml \
  --capabilities CAPABILITY_NAMED_IAM --no-fail-on-empty-changeset \
  --parameter-overrides ReservedConcurrency=$RESERVED --tags project=$P pci-scope=cde

aws cloudformation describe-stacks --stack-name $P-app --query "Stacks[0].Outputs" --output table
