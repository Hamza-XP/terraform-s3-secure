#!/bin/bash

# ============================================================================
# INFRASTRUCTURE MONITORING SCRIPT
# Real-time monitoring and health checks for deployed infrastructure
# ============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

# Function to print colored output
print_header() {
    echo -e "\n${PURPLE}=== $1 ===${NC}"
}

print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

# Function to check if required tools are installed
check_prerequisites() {
    print_header "CHECKING PREREQUISITES"

    local missing_tools=()

    if ! command -v aws &> /dev/null; then
        missing_tools+=("aws-cli")
    fi

    if ! command -v terraform &> /dev/null; then
        missing_tools+=("terraform")
    fi

    if ! command -v jq &> /dev/null; then
        missing_tools+=("jq")
    fi

    if ! command -v curl &> /dev/null; then
        missing_tools+=("curl")
    fi

    if [ ${#missing_tools[@]} -ne 0 ]; then
        print_error "Missing required tools: ${missing_tools[*]}"
        echo "Please install the missing tools and try again."
        exit 1
    fi

    print_success "All prerequisites are installed"
}

# Function to get Terraform outputs
get_terraform_outputs() {
    print_header "RETRIEVING INFRASTRUCTURE DETAILS"

    if [ ! -f "terraform.tfstate" ] && [ ! -d ".terraform" ]; then
        print_error "Terraform state not found. Run terraform init and apply first."
        exit 1
    fi

    # Get key infrastructure details
    DISTRIBUTION_ID=$(terraform output -raw cloudfront_distribution_id 2>/dev/null || echo "")
    DOMAIN_NAME=$(terraform output -raw cloudfront_domain_name 2>/dev/null || echo "")
    S3_BUCKET=$(terraform output -raw s3_bucket_name 2>/dev/null || echo "")
    WAF_ARN=$(terraform output -raw waf_web_acl_arn 2>/dev/null || echo "")

    if [ -z "$DISTRIBUTION_ID" ] || [ -z "$DOMAIN_NAME" ] || [ -z "$S3_BUCKET" ]; then
        print_error "Failed to retrieve Terraform outputs. Ensure infrastructure is deployed."
        exit 1
    fi

    print_success "Retrieved infrastructure details"
    echo "  Distribution ID: $DISTRIBUTION_ID"
    echo "  CloudFront Domain: $DOMAIN_NAME"
    echo "  S3 Bucket: $S3_BUCKET"
}

# Function to check CloudFront distribution status
check_cloudfront() {
    print_header "CLOUDFRONT DISTRIBUTION STATUS"

    local status=$(aws cloudfront get-distribution --id "$DISTRIBUTION_ID" --query 'Distribution.Status' --output text)
    local enabled=$(aws cloudfront get-distribution --id "$DISTRIBUTION_ID" --query 'Distribution.DistributionConfig.Enabled' --output text)

    if [ "$status" == "Deployed" ] && [ "$enabled" == "True" ]; then
        print_success "CloudFront distribution is deployed and enabled"
    else
        print_warning "CloudFront distribution status: $status, enabled: $enabled"
    fi

    # Check origins
    local origin_count=$(aws cloudfront get-distribution --id "$DISTRIBUTION_ID" --query 'length(Distribution.DistributionConfig.Origins.Items)' --output text)
    print_status "Origins configured: $origin_count"

    # Check cache behaviors
    local behavior_count=$(aws cloudfront get-distribution --id "$DISTRIBUTION_ID" --query 'length(Distribution.DistributionConfig.CacheBehaviors.Items)' --output text)
    print_status "Cache behaviors: $((behavior_count + 1))" # +1 for default behavior
}

# Function to test website accessibility
test_website_access() {
    print_header "WEBSITE ACCESSIBILITY TEST"

    local url="https://$DOMAIN_NAME"

    print_status "Testing HTTPS access to $url"

    # Test HTTP status
    local http_code=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$url" || echo "000")

    if [ "$http_code" == "200" ]; then
        print_success "Website is accessible (HTTP $http_code)"
    elif [ "$http_code" == "000" ]; then
        print_error "Website is not reachable (connection failed)"
        return 1
    else
        print_warning "Website returned HTTP $http_code"
    fi

    # Test response time
    local response_time=$(curl -s -o /dev/null -w "%{time_total}" --max-time 10 "$url" 2>/dev/null || echo "timeout")

    if [ "$response_time" != "timeout" ]; then
        print_status "Response time: ${response_time}s"

        # Evaluate response time
        if (( $(echo "$response_time < 1.0" | bc -l) )); then
            print_success "Good response time"
        elif (( $(echo "$response_time < 3.0" | bc -l) )); then
            print_warning "Moderate response time"
        else
            print_error "Slow response time"
        fi
    else
        print_error "Request timed out"
    fi

    # Test SSL certificate
    print_status "Checking SSL certificate..."
    local ssl_info=$(echo | openssl s_client -servername "$DOMAIN_NAME" -connect "$DOMAIN_NAME:443" 2>/dev/null | openssl x509 -noout -dates 2>/dev/null || echo "SSL check failed")

    if [ "$ssl_info" != "SSL check failed" ]; then
        print_success "SSL certificate is valid"
        echo "$ssl_info" | while read line; do
            echo "  $line"
        done
    else
        print_error "SSL certificate check failed"
    fi
}

# Function to check S3 bucket status
check_s3_bucket() {
    print_header "S3 BUCKET STATUS"

    # Check if bucket exists and is accessible
    if aws s3 ls "s3://$S3_BUCKET" >/dev/null 2>&1; then
        print_success "S3 bucket is accessible"

        # Count objects
        local object_count=$(aws s3 ls "s3://$S3_BUCKET" --recursive | wc -l)
        print_status "Objects in bucket: $object_count"

        # Check bucket size
        local bucket_size=$(aws s3 ls "s3://$S3_BUCKET" --recursive --human-readable --summarize | grep "Total Size" | awk '{print $3, $4}')
        print_status "Bucket size: $bucket_size"

        # Check versioning
        local versioning=$(aws s3api get-bucket-versioning --bucket "$S3_BUCKET" --query 'Status' --output text 2>/dev/null || echo "None")
        print_status "Versioning: $versioning"

        # Check encryption
        local encryption=$(aws s3api get-bucket-encryption --bucket "$S3_BUCKET" --query 'ServerSideEncryptionConfiguration.Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm' --output text 2>/dev/null || echo "None")
        print_status "Encryption: $encryption"

    else
        print_error "S3 bucket is not accessible"
    fi
}

# Function to check WAF status
check_waf() {
    print_header "WAF WEB ACL STATUS"

    if [ -n "$WAF_ARN" ]; then
        local waf_id=$(echo "$WAF_ARN" | cut -d'/' -f3)

        # Get WAF details
        local waf_info=$(aws wafv2 get-web-acl --scope CLOUDFRONT --id "$waf_id" --name "$(terraform output -raw project_name)-$(terraform output -raw environment)-waf" 2>/dev/null || echo "")

        if [ -n "$waf_info" ]; then
            print_success "WAF Web ACL is active"

            # Count rules
            local rule_count=$(echo "$waf_info" | jq '.WebACL.Rules | length' 2>/dev/null || echo "unknown")
            print_status "Rules configured: $rule_count"

            # Check default action
            local default_action=$(echo "$waf_info" | jq -r '.WebACL.DefaultAction | keys[0]' 2>/dev/null || echo "unknown")
            print_status "Default action: $default_action"

        else
            print_error "WAF Web ACL not found or not accessible"
        fi
    else
        print_warning "WAF ARN not available"
    fi
}

# Function to check CloudWatch alarms
check_cloudwatch_alarms() {
    print_header "CLOUDWATCH ALARMS STATUS"

    local project_name=$(terraform output -raw project_name 2>/dev/null || echo "secure-website")

    # Get alarms for this project
    local alarms=$(aws cloudwatch describe-alarms --alarm-name-prefix "$project_name" --query 'MetricAlarms[].{Name:AlarmName,State:StateValue,Reason:StateReason}' --output table 2>/dev/null || echo "")

    if [ -n "$alarms" ] && [ "$alarms" != "" ]; then
        echo "$alarms"

        # Count alarm states
        local ok_count=$(aws cloudwatch describe-alarms --alarm-name-prefix "$project_name" --state-value OK --query 'length(MetricAlarms)' --output text 2>/dev/null || echo "0")
        local alarm_count=$(aws cloudwatch describe-alarms --alarm-name-prefix "$project_name" --state-value ALARM --query 'length(MetricAlarms)' --output text 2>/dev/null || echo "0")
        local insufficient_count=$(aws cloudwatch describe-alarms --alarm-name-prefix "$project_name" --state-value INSUFFICIENT_DATA --query 'length(MetricAlarms)' --output text 2>/dev/null || echo "0")

        print_status "Alarm summary - OK: $ok_count, ALARM: $alarm_count, INSUFFICIENT_DATA: $insufficient_count"

        if [ "$alarm_count" -gt 0 ]; then
            print_error "$alarm_count alarms are currently in ALARM state"
        else
            print_success "No alarms are currently triggered"
        fi
    else
        print_warning "No CloudWatch alarms found for this project"
    fi
}

# Function to get recent CloudWatch metrics
get_recent_metrics() {
    print_header "RECENT CLOUDFRONT METRICS (Last 24 Hours)"

    local end_time=$(date -u +"%Y-%m-%dT%H:%M:%S")
    local start_time=$(date -u -d '24 hours ago' +"%Y-%m-%dT%H:%M:%S")

    # Get request count
    local requests=$(aws cloudwatch get-metric-statistics \
        --namespace AWS/CloudFront \
        --metric-name Requests \
        --dimensions Name=DistributionId,Value="$DISTRIBUTION_ID" \
        --start-time "$start_time" \
        --end-time "$end_time" \
        --period 3600 \
        --statistics Sum \
        --query 'Datapoints[0].Sum' \
        --output text 2>/dev/null || echo "N
