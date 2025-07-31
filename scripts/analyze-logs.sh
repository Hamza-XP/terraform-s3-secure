#!/bin/bash

# ============================================================================
# LOG ANALYSIS SCRIPT
# Automated analysis of CloudFront and WAF logs using AWS Athena
# ============================================================================

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
NC='\033[0m' # No Color

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

# Check prerequisites
check_prerequisites() {
    print_header "CHECKING PREREQUISITES"

    if ! command -v aws &> /dev/null; then
        print_error "AWS CLI not found. Please install AWS CLI."
        exit 1
    fi

    if ! command -v terraform &> /dev/null; then
        print_error "Terraform not found. Please install Terraform."
        exit 1
    fi

    print_success "Prerequisites check passed"
}

# Get infrastructure details
get_infrastructure_details() {
    print_header "RETRIEVING INFRASTRUCTURE DETAILS"

    LOGS_BUCKET=$(terraform output -raw logs_bucket_name 2>/dev/null || echo "")
    PROJECT_NAME=$(terraform output -raw project_name 2>/dev/null || echo "secure-website")
    ENVIRONMENT=$(terraform output -raw environment 2>/dev/null || echo "production")
    REGION=$(aws configure get region || echo "us-east-1")

    if [ -z "$LOGS_BUCKET" ]; then
        print_error "Could not retrieve logs bucket name. Ensure infrastructure is deployed."
        exit 1
    fi

    print_success "Retrieved infrastructure details"
    echo "  Logs Bucket: $LOGS_BUCKET"
    echo "  Project: $PROJECT_NAME"
    echo "  Environment: $ENVIRONMENT"
    echo "  Region: $REGION"
}

# Setup Athena database and tables
setup_athena() {
    print_header "SETTING UP ATHENA DATABASE AND TABLES"

    DATABASE_NAME="${PROJECT_NAME}_${ENVIRONMENT}_logs"
    ATHENA_RESULTS_LOCATION="s3://$LOGS_BUCKET/athena-results/"

    # Create database
    print_status "Creating Athena database: $DATABASE_NAME"

    aws athena start-query-execution \
        --query-string "CREATE DATABASE IF NOT EXISTS $DATABASE_NAME" \
        --result-configuration "OutputLocation=$ATHENA_RESULTS_LOCATION" \
        --region "$REGION" > /dev/null

    # Wait for query to complete
    sleep 5

    # Create CloudFront logs table
    print_status "Creating CloudFront logs table..."

    CLOUDFRONT_TABLE_QUERY="CREATE EXTERNAL TABLE IF NOT EXISTS $DATABASE_NAME.cloudfront_logs (
        date_time timestamp,
        x_edge_location string,
        sc_bytes bigint,
        c_ip string,
        cs_method string,
        cs_host string,
        cs_uri_stem string,
        sc_status int,
        cs_referer string,
        cs_user_agent string,
        cs_uri_query string,
        cs_cookie string,
        x_edge_result_type string,
        x_edge_request_id string,
        x_host_header string,
        cs_protocol string,
        cs_bytes bigint,
        time_taken double,
        x_forwarded_for string,
        ssl_protocol string,
        ssl_cipher string,
        x_edge_response_result_type string,
        cs_protocol_version string,
        fle_status string,
        fle_encrypted_fields int,
        c_port int,
        time_to_first_byte double,
        x_edge_detailed_result_type string,
        sc_content_type string,
        sc_content_len bigint,
        sc_range_start bigint,
        sc_range_end bigint
    )
    STORED AS INPUTFORMAT 'org.apache.hadoop.mapred.TextInputFormat'
    OUTPUTFORMAT 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat'
    LOCATION 's3://$LOGS_BUCKET/cloudfront-logs/'
    TBLPROPERTIES (
        'skip.header.line.count'='2',
        'field.delim'='\t'
    )"

    aws athena start-query-execution \
        --query-string "$CLOUDFRONT_TABLE_QUERY" \
        --result-configuration "OutputLocation=$ATHENA_RESULTS_LOCATION" \
        --query-execution-context "Database=$DATABASE_NAME" \
        --region "$REGION" > /dev/null

    # Wait for table creation
    sleep 10

    print_success "Athena setup completed"
}

# Analyze CloudFront logs
analyze_cloudfront_logs() {
    print_header "ANALYZING CLOUDFRONT LOGS"

    DATABASE_NAME="${PROJECT_NAME}_${ENVIRONMENT}_logs"
    ATHENA_RESULTS_LOCATION="s3://$LOGS_BUCKET/athena-results/"

    # Top 10 client IPs
    print_status "Getting top 10 client IPs..."

    TOP_IPS_QUERY="SELECT c_ip, COUNT(*) as request_count,
                   SUM(sc_bytes) as total_bytes,
                   AVG(time_taken) as avg_response_time
                   FROM $DATABASE_NAME.cloudfront_logs
                   WHERE date_time >= current_timestamp - interval '24' hour
                   GROUP BY c_ip
                   ORDER BY request_count DESC
                   LIMIT 10"

    QUERY_ID=$(aws athena start-query-execution \
        --query-string "$TOP_IPS_QUERY" \
        --result-configuration "OutputLocation=$ATHENA_RESULTS_LOCATION" \
        --query-execution-context "Database=$DATABASE_NAME" \
        --region "$REGION" \
        --query 'QueryExecutionId' --output text)

    # Wait for query completion
    wait_for_query "$QUERY_ID"

    # Get results
    aws athena get-query-results --query-execution-id "$QUERY_ID" --region "$REGION" \
        --query 'ResultSet.Rows[*].Data[*].VarCharValue' --output table

    # Status code analysis
    print_status "Analyzing HTTP status codes..."

    STATUS_QUERY="SELECT sc_status, COUNT(*) as count,
                  ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER(), 2) as percentage
                  FROM $DATABASE_NAME.cloudfront_logs
                  WHERE date_time >= current_timestamp - interval '24' hour
                  GROUP BY sc_status
                  ORDER BY count DESC"

    QUERY_ID=$(aws athena start-query-execution \
        --query-string "$STATUS_QUERY" \
        --result-configuration "OutputLocation=$ATHENA_RESULTS_LOCATION" \
        --query-execution-context "Database=$DATABASE_NAME" \
        --region "$REGION" \
        --query 'QueryExecutionId' --output text)

    wait_for_query "$QUERY_ID"

    aws athena get-query-results --query-execution-id "$QUERY_ID" --region "$REGION" \
        --query 'ResultSet.Rows[*].Data[*].VarCharValue' --output table

    # Top requested URIs
    print_status "Getting top requested URIs..."

    TOP_URIS_QUERY="SELECT cs_uri_stem, COUNT(*) as request_count,
                    SUM(sc_bytes) as total_bytes_served
                    FROM $DATABASE_NAME.cloudfront_logs
                    WHERE date_time >= current_timestamp - interval '24' hour
                    GROUP BY cs_uri_stem
                    ORDER BY request_count DESC
                    LIMIT 10"

    QUERY_ID=$(aws athena start-query-execution \
        --query-string "$TOP_URIS_QUERY" \
        --result-configuration "OutputLocation=$ATHENA_RESULTS_LOCATION" \
        --query-execution-context "Database=$DATABASE_NAME" \
        --region "$REGION" \
        --query 'QueryExecutionId' --output text)

    wait_for_query "$QUERY_ID"

    aws athena get-query-results --query-execution-id "$QUERY_ID" --region "$REGION" \
        --query 'ResultSet.Rows[*].Data[*].VarCharValue' --output table
}

# Analyze WAF logs from CloudWatch
analyze_waf_logs() {
    print_header "ANALYZING WAF LOGS"

    WAF_LOG_GROUP="aws-waf-logs-${PROJECT_NAME}-${ENVIRONMENT}"

    # Check if WAF logs exist
    if ! aws logs describe-log-groups --log-group-name-prefix "$WAF_LOG_GROUP" --region "$REGION" --query 'logGroups[0]' --output text &>/dev/null; then
        print_warning "WAF logs not found. WAF logging may not be configured or no blocked requests yet."
        return
    fi

    print_status "Getting blocked requests by country (last 24 hours)..."

    # Get blocked requests by country
    BLOCKED_BY_COUNTRY=$(aws logs start-query \
        --log-group-name "$WAF_LOG_GROUP" \
        --start-time $(date -d '24 hours ago' +%s) \
        --end-time $(date +%s) \
        --query-string 'fields @timestamp, action, httpRequest.country, httpRequest.clientIp
                        | filter action = "BLOCK"
                        | stats count() by httpRequest.country
                        | sort count desc
                        | limit 10' \
        --region "$REGION" \
        --query 'queryId' --output text)

    # Wait for query to complete
    sleep 10

    # Get results
    aws logs get-query-results --query-id "$BLOCKED_BY_COUNTRY" --region "$REGION" \
        --query 'results[*][*].value' --output table

    print_status "Getting blocked requests by rule (last 24 hours)..."

    # Get blocked requests by rule
    BLOCKED_BY_RULE=$(aws logs start-query \
        --log-group-name "$WAF_LOG_GROUP" \
        --start-time $(date -d '24 hours ago' +%s) \
        --end-time $(date +%s) \
        --query-string 'fields @timestamp, action, terminatingRuleId, terminatingRuleType
                        | filter action = "BLOCK"
                        | stats count() by terminatingRuleId
                        | sort count desc
                        | limit 10' \
        --region "$REGION" \
        --query 'queryId' --output text)

    sleep 10

    aws logs get-query-results --query-id "$BLOCKED_BY_RULE" --region "$REGION" \
        --query 'results[*][*].value' --output table

    print_status "Getting top blocked IPs (last 24 hours)..."

    # Get top blocked IPs
    BLOCKED_IPS=$(aws logs start-query \
        --log-group-name "$WAF_LOG_GROUP" \
        --start-time $(date -d '24 hours ago' +%s) \
        --end-time $(date +%s) \
        --query-string 'fields @timestamp, action, httpRequest.clientIp, httpRequest.country
                        | filter action = "BLOCK"
                        | stats count() by httpRequest.clientIp, httpRequest.country
                        | sort count desc
                        | limit 15' \
        --region "$REGION" \
        --query 'queryId' --output text)

    sleep 10

    aws logs get-query-results --query-id "$BLOCKED_IPS" --region "$REGION" \
        --query 'results[*][*].value' --output table
}

# Generate security report
generate_security_report() {
    print_header "GENERATING SECURITY REPORT"

    REPORT_FILE="security-report-$(date +%Y%m%d-%H%M%S).txt"

    {
        echo "SECURITY ANALYSIS REPORT"
        echo "Generated: $(date)"
        echo "Project: $PROJECT_NAME"
        echo "Environment: $ENVIRONMENT"
        echo "=========================="
        echo ""

        # Check for recent alarms
        echo "RECENT CLOUDWATCH ALARMS:"
        aws cloudwatch describe-alarms \
            --alarm-name-prefix "$PROJECT_NAME" \
            --state-value ALARM \
            --query 'MetricAlarms[*].{Name:AlarmName,State:StateValue,Reason:StateReason,Time:StateUpdatedTimestamp}' \
            --output table --region "$REGION" 2>/dev/null || echo "No active alarms"

        echo ""
        echo "RECENT BLOCKED REQUESTS SUMMARY:"

        # Get WAF metrics from CloudWatch
        local blocked_requests=$(aws cloudwatch get-metric-statistics \
            --namespace AWS/WAFV2 \
            --metric-name BlockedRequests \
            --dimensions Name=WebACL,Value="${PROJECT_NAME}-${ENVIRONMENT}-waf" Name=Rule,Value=ALL Name=Region,Value=CloudFront \
            --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%S) \
            --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
            --period 3600 \
            --statistics Sum \
            --query 'Datapoints[0].Sum' \
            --output text --region "$REGION" 2>/dev/null || echo "0")

        echo "Total blocked requests (24h): $blocked_requests"

        local allowed_requests=$(aws cloudwatch get-metric-statistics \
            --namespace AWS/WAFV2 \
            --metric-name AllowedRequests \
            --dimensions Name=WebACL,Value="${PROJECT_NAME}-${ENVIRONMENT}-waf" Name=Rule,Value=ALL Name=Region,Value=CloudFront \
            --start-time $(date -u -d '24 hours ago' +%Y-%m-%dT%H:%M:%S) \
            --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
            --period 3600 \
            --statistics Sum \
            --query 'Datapoints[0].Sum' \
            --output text --region "$REGION" 2>/dev/null || echo "0")

        echo "Total allowed requests (24h): $allowed_requests"

        if [ "$blocked_requests" != "0" ] && [ "$allowed_requests" != "0" ]; then
            local block_rate=$(echo "scale=2; $blocked_requests * 100 / ($blocked_requests + $allowed_requests)" | bc 2>/dev/null || echo "N/A")
            echo "Block rate: ${block_rate}%"
        fi

        echo ""
        echo "RECOMMENDATIONS:"

        # Security recommendations based on metrics
        if [ "$blocked_requests" -gt 1000 ]; then
            echo "- HIGH: Consider reviewing WAF rules - high number of blocked requests detected"
        fi

        if [ "$blocked_requests" -eq 0 ]; then
            echo "- INFO: No blocked requests in 24h - WAF rules may need adjustment or traffic is clean"
        fi

        echo "- Review CloudWatch dashboard for detailed metrics"
        echo "- Monitor SSL certificate expiration"
        echo "- Verify backup and disaster recovery procedures"
        echo "- Conduct regular security assessments"

    } > "$REPORT_FILE"

    print_success "Security report generated: $REPORT_FILE"

    # Display summary
    cat "$REPORT_FILE"
}

# Wait for Athena query to complete
wait_for_query() {
    local query_id=$1
    local max_attempts=30
    local attempt=0

    while [ $attempt -lt $max_attempts ]; do
        local status=$(aws athena get-query-execution --query-execution-id "$query_id" --region "$REGION" --query 'QueryExecution.Status.State' --output text)

        case $status in
            "SUCCEEDED")
                return 0
                ;;
            "FAILED"|"CANCELLED")
                print_error "Query failed or was cancelled"
                return 1
                ;;
            "RUNNING"|"QUEUED")
                sleep 3
                attempt=$((attempt + 1))
                ;;
        esac
    done

    print_error "Query timed out"
    return 1
}

# Generate cost analysis
generate_cost_analysis() {
    print_header "COST ANALYSIS"

    print_status "Retrieving cost information..."

    # Get CloudFront costs (last 30 days)
    local start_date=$(date -d '30 days ago' +%Y-%m-%d)
    local end_date=$(date +%Y-%m-%d)

    local cloudfront_cost=$(aws ce get-cost-and-usage \
        --time-period Start="$start_date",End="$end_date" \
        --granularity MONTHLY \
        --metrics BlendedCost \
        --group-by Type=DIMENSION,Key=SERVICE \
        --filter file://<(cat <<EOF
{
    "Dimensions": {
        "Key": "SERVICE",
        "Values": ["Amazon CloudFront"]
    }
}
EOF
) \
        --query 'ResultsByTime[0].Groups[?Keys[0]==`Amazon CloudFront`].Metrics.BlendedCost.Amount' \
        --output text --region "$REGION" 2>/dev/null || echo "N/A")

    echo "CloudFront cost (30 days): \${cloudfront_cost:-N/A}"

    # Get S3 costs
    local s3_cost=$(aws ce get-cost-and-usage \
        --time-period Start="$start_date",End="$end_date" \
        --granularity MONTHLY \
        --metrics BlendedCost \
        --group-by Type=DIMENSION,Key=SERVICE \
        --filter file://<(cat <<EOF
{
    "Dimensions": {
        "Key": "SERVICE",
        "Values": ["Amazon Simple Storage Service"]
    }
}
EOF
) \
        --query 'ResultsByTime[0].Groups[?Keys[0]==`Amazon Simple Storage Service`].Metrics.BlendedCost.Amount' \
        --output text --region "$REGION" 2>/dev/null || echo "N/A")

    echo "S3 cost (30 days): \${s3_cost:-N/A}"

    # Storage usage
    local bucket_size=$(aws s3 ls s3://$LOGS_BUCKET --recursive --human-readable --summarize | grep "Total Size" | awk '{print $3, $4}' || echo "N/A")
    echo "Logs bucket size: $bucket_size"

    print_status "Cost optimization recommendations:"
    echo "- Review log retention policies"
    echo "- Consider S3 Intelligent Tiering for logs"
    echo "- Monitor CloudFront cache hit ratios"
    echo "- Use CloudFront price classes efficiently"
}

# Main menu
show_menu() {
    echo -e "${PURPLE}"
    echo "╔════════════════════════════════════════════════════════════════╗"
    echo "║                      LOG ANALYSIS TOOL                         ║"
    echo "║              CloudFront & WAF Log Analytics                    ║"
    echo "╚════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo ""
    echo "1. Setup Athena (required for CloudFront log analysis)"
    echo "2. Analyze CloudFront logs"
    echo "3. Analyze WAF logs"
    echo "4. Generate security report"
    echo "5. Cost analysis"
    echo "6. Run all analyses"
    echo "0. Exit"
    echo ""
    read -p "Select an option: " choice
}

# Main execution
main() {
    check_prerequisites
    get_infrastructure_details

    if [ "$#" -eq 0 ]; then
        # Interactive mode
        while true; do
            show_menu
            case $choice in
                1)
                    setup_athena
                    ;;
                2)
                    analyze_cloudfront_logs
                    ;;
                3)
                    analyze_waf_logs
                    ;;
                4)
                    generate_security_report
                    ;;
                5)
                    generate_cost_analysis
                    ;;
                6)
                    setup_athena
                    analyze_cloudfront_logs
                    analyze_waf_logs
                    generate_security_report
                    generate_cost_analysis
                    ;;
                0)
                    print_success "Goodbye!"
                    exit 0
                    ;;
                *)
                    print_error "Invalid option. Please try again."
                    ;;
            esac
            echo ""
            read -p "Press Enter to continue..."
        done
    else
        # Command line mode
        case "$1" in
            setup)
                setup_athena
                ;;
            cloudfront)
                analyze_cloudfront_logs
                ;;
            waf)
                analyze_waf_logs
                ;;
            security)
                generate_security_report
                ;;
            cost)
                generate_cost_analysis
                ;;
            all)
                setup_athena
                analyze_cloudfront_logs
                analyze_waf_logs
                generate_security_report
                generate_cost_analysis
                ;;
            *)
                echo "Usage: $0 [setup|cloudfront|waf|security|cost|all]"
                exit 1
                ;;
        esac
    fi
}

# Run main function
main "$@"
