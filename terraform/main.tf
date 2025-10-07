# ============================================================================
# TERRAFORM CONFIGURATION
# Production-Ready S3 + CloudFront + WAF + SSL + Monitoring Setup
# ============================================================================

terraform {
  required_version = ">= 1.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# ============================================================================
# VARIABLES
# ============================================================================

#variable "domain_name" {
#  description = "The domain name for the website"
#  type        = string
#  default     = "example.com"
#}

# MODIFIED:
variable "domain_name" {
  description = "The domain name for the website (optional - leave empty to use CloudFront domain)"
  type        = string
  default     = ""
}

# ADDED:
variable "use_custom_domain" {
  description = "Set to true if using a custom domain, false to use CloudFront domain only"
  type        = bool
  default     = false
}

variable "environment" {
  description = "Environment name"
  type        = string
  default     = "production"
}

variable "project_name" {
  description = "Name of the project"
  type        = string
  default     = "secure-website"
}

variable "allowed_countries" {
  description = "List of allowed country codes for geo-blocking"
  type        = list(string)
  default     = ["US", "CA", "GB", "DE", "FR"]
}

# ============================================================================
# DATA SOURCES
# ============================================================================

data "aws_caller_identity" "current" {}

data "aws_region" "current" {}

# ============================================================================
# S3 BUCKET FOR WEBSITE CONTENT
# ============================================================================

resource "aws_s3_bucket" "website" {
  bucket = "${var.project_name}-${var.environment}-${random_id.bucket_suffix.hex}"

  tags = {
    Name        = "${var.project_name}-website"
    Environment = var.environment
    Purpose     = "Static Website Hosting"
  }
}

resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket_versioning" "website" {
  bucket = aws_s3_bucket.website.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "website" {
  bucket = aws_s3_bucket.website.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "website" {
  bucket = aws_s3_bucket.website.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# ============================================================================
# S3 BUCKET FOR ACCESS LOGS
# ============================================================================

resource "aws_s3_bucket" "logs" {
  bucket = "${var.project_name}-${var.environment}-logs-${random_id.bucket_suffix.hex}"

  tags = {
    Name        = "${var.project_name}-logs"
    Environment = var.environment
    Purpose     = "CloudFront and WAF Access Logs"
  }
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id

  rule {
    id     = "cloudfront_log_retention"
    status = "Enabled"

    filter {
      prefix = "cloudfront-logs/"
    }

    expiration {
      days = 90
    }

    noncurrent_version_expiration {
      noncurrent_days = 30
    }
  }

  rule {
    id     = "waf_log_retention"
    status = "Enabled"

    filter {
      prefix = "waf-logs/"
    }

    expiration {
      days = 30
    }

    noncurrent_version_expiration {
      noncurrent_days = 7
    }
  }

  rule {
    id     = "athena_results_cleanup"
    status = "Enabled"

    filter {
      prefix = "athena-results/"
    }

    expiration {
      days = 7
    }
  }
}

# ============================================================================
# CLOUDWATCH LOG GROUP FOR WAF
# ============================================================================

resource "aws_cloudwatch_log_group" "waf_logs" {
  name              = "aws-waf-logs-${var.project_name}-${var.environment}"
  retention_in_days = 30

  tags = {
    Name        = "${var.project_name}-waf-logs"
    Environment = var.environment
    Purpose     = "WAF Request Logs"
  }
}

# ============================================================================
# KINESIS FIREHOSE FOR WAF LOGS TO S3
# ============================================================================

resource "aws_iam_role" "firehose_delivery_role" {
  name = "${var.project_name}-${var.environment}-firehose-delivery-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "firehose.amazonaws.com"
        }
      }
    ]
  })

  tags = {
    Name        = "${var.project_name}-firehose-role"
    Environment = var.environment
  }
}

resource "aws_iam_role_policy" "firehose_delivery_policy" {
  name = "${var.project_name}-${var.environment}-firehose-delivery-policy"
  role = aws_iam_role.firehose_delivery_role.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:AbortMultipartUpload",
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:ListBucketMultipartUploads",
          "s3:PutObject"
        ]
        Resource = [
          aws_s3_bucket.logs.arn,
          "${aws_s3_bucket.logs.arn}/*"
        ]
      },
      {
        Effect = "Allow"
        Action = [
          "logs:PutLogEvents"
        ]
        Resource = "${aws_cloudwatch_log_group.waf_logs.arn}:*"
      }
    ]
  })
}

resource "aws_kinesis_firehose_delivery_stream" "waf_logs" {
  name        = "${var.project_name}-${var.environment}-waf-logs"
  destination = "s3"

  s3_configuration {
    role_arn           = aws_iam_role.firehose_delivery_role.arn
    bucket_arn         = aws_s3_bucket.logs.arn
    prefix             = "waf-logs/year=!{timestamp:yyyy}/month=!{timestamp:MM}/day=!{timestamp:dd}/hour=!{timestamp:HH}/"
    error_output_prefix = "waf-logs-errors/"
    buffer_size        = 5
    buffer_interval    = 300
    compression_format = "GZIP"

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.waf_logs.name
      log_stream_name = "S3Delivery"
    }
  }

}

# ============================================================================
# WAF LOGGING CONFIGURATION
# ============================================================================

resource "aws_wafv2_web_acl_logging_configuration" "website" {
  resource_arn            = aws_wafv2_web_acl.website.arn
  log_destination_configs = [aws_kinesis_firehose_delivery_stream.waf_logs.arn]

  redacted_fields {
    single_header {
      name = "authorization"
    }
  }

  redacted_fields {
    single_header {
      name = "cookie"
    }
  }

  logging_filter {
    default_behavior = "KEEP"

    filter {
      behavior = "KEEP"
      condition {
        action_condition {
          action = "BLOCK"
        }
      }
      requirement = "MEETS_ANY"
    }

    filter {
      behavior = "DROP"
      condition {
        action_condition {
          action = "ALLOW"
        }
      }
      condition {
        label_name_condition {
          label_name = "awswaf:managed:aws:core-rule-set:NoUserAgent_Header"
        }
      }
      requirement = "MEETS_ALL"
    }
  }
}

# ============================================================================
# SSL CERTIFICATE (ACM)
# ============================================================================

# COMMENTED OUT:
/*
resource "aws_acm_certificate" "website" {
  domain_name               = var.domain_name
  subject_alternative_names = ["*.${var.domain_name}"]
  validation_method         = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name        = "${var.project_name}-ssl-cert"
    Environment = var.environment
  }
}
*/

# ============================================================================
# CLOUDFRONT ORIGIN ACCESS CONTROL
# ============================================================================

resource "aws_cloudfront_origin_access_control" "website" {
  name                              = "${var.project_name}-oac"
  description                       = "OAC for ${var.project_name} website"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

# ============================================================================
# WAF WEB ACL
# ============================================================================

resource "aws_wafv2_web_acl" "website" {
  name  = "${var.project_name}-${var.environment}-waf"
  scope = "CLOUDFRONT"

  default_action {
    allow {}
  }

  # Rate limiting rule
  rule {
    name     = "RateLimitRule"
    priority = 1

    override_action {
      none {}
    }

    statement {
      rate_based_statement {
        limit              = 2000
        aggregate_key_type = "IP"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "RateLimitRule"
      sampled_requests_enabled   = true
    }

    action {
      block {}
    }
  }

  # AWS Managed Rules - Core Rule Set
  rule {
    name     = "AWSManagedRulesCommonRuleSet"
    priority = 2

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesCommonRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "CommonRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }

  # AWS Managed Rules - Known Bad Inputs
  rule {
    name     = "AWSManagedRulesKnownBadInputsRuleSet"
    priority = 3

    override_action {
      none {}
    }

    statement {
      managed_rule_group_statement {
        name        = "AWSManagedRulesKnownBadInputsRuleSet"
        vendor_name = "AWS"
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "KnownBadInputsRuleSetMetric"
      sampled_requests_enabled   = true
    }
  }

  # Geo-blocking rule
  rule {
    name     = "GeoBlockingRule"
    priority = 4

    action {
      block {}
    }

    statement {
      not_statement {
        statement {
          geo_match_statement {
            country_codes = var.allowed_countries
          }
        }
      }
    }

    visibility_config {
      cloudwatch_metrics_enabled = true
      metric_name                = "GeoBlockingRule"
      sampled_requests_enabled   = true
    }
  }

  tags = {
    Name        = "${var.project_name}-waf"
    Environment = var.environment
  }

  visibility_config {
    cloudwatch_metrics_enabled = true
    metric_name                = "${var.project_name}WebAcl"
    sampled_requests_enabled   = true
  }
}

# ============================================================================
# CLOUDFRONT DISTRIBUTION
# ============================================================================

resource "aws_cloudfront_distribution" "website" {
  origin {
    domain_name              = aws_s3_bucket.website.bucket_regional_domain_name
    origin_access_control_id = aws_cloudfront_origin_access_control.website.id
    origin_id                = "S3-${aws_s3_bucket.website.bucket}"
  }

  enabled             = true
  is_ipv6_enabled     = true
  comment             = "${var.project_name} distribution"
  default_root_object = "index.html"

  logging_config {
    include_cookies = false
    bucket          = aws_s3_bucket.logs.bucket_domain_name
    prefix          = "cloudfront-logs/"
  }

  aliases = [var.domain_name, "www.${var.domain_name}"]

  default_cache_behavior {
    allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "S3-${aws_s3_bucket.website.bucket}"

    forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    }

    viewer_protocol_policy     = "redirect-to-https"
    min_ttl                    = 0
    default_ttl                = 3600
    max_ttl                    = 86400
    compress                   = true
    response_headers_policy_id = aws_cloudfront_response_headers_policy.security_headers.id
  }

  # Cache behavior for static assets
  ordered_cache_behavior {
    path_pattern     = "*.png"
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    cached_methods   = ["GET", "HEAD", "OPTIONS"]
    target_origin_id = "S3-${aws_s3_bucket.website.bucket}"

    forwarded_values {
      query_string = false
      cookies {
        forward = "none"
      }
    }

    min_ttl                = 0
    default_ttl            = 86400
    max_ttl                = 31536000
    compress               = true
    viewer_protocol_policy = "redirect-to-https"
  }

  price_class = "PriceClass_100"

  restrictions {
    geo_restriction {
      restriction_type = "whitelist"
      locations        = var.allowed_countries
    }
  }

  viewer_certificate {
    acm_certificate_arn = aws_acm_certificate.website.arn
    ssl_support_method  = "sni-only"
  }

  web_acl_id = aws_wafv2_web_acl.website.arn

  custom_error_response {
    error_code         = 404
    response_code      = 200
    response_page_path = "/index.html"
  }

  custom_error_response {
    error_code         = 403
    response_code      = 200
    response_page_path = "/index.html"
  }

  tags = {
    Name        = "${var.project_name}-distribution"
    Environment = var.environment
  }
}

# ============================================================================
# CLOUDFRONT RESPONSE HEADERS POLICY
# ============================================================================

resource "aws_cloudfront_response_headers_policy" "security_headers" {
  name = "${var.project_name}-security-headers"

  security_headers_config {
    strict_transport_security {
      access_control_max_age_sec = 31536000
      include_subdomains         = true
      preload                    = true
      override                   = true
    }
    content_type_options {
      override = true
    }
    frame_options {
      frame_option = "DENY"
      override     = true
    }
    referrer_policy {
      referrer_policy = "strict-origin-when-cross-origin"
      override        = true
    }
  }
}

# ============================================================================
# S3 BUCKET POLICY FOR CLOUDFRONT
# ============================================================================

resource "aws_s3_bucket_policy" "website" {
  bucket = aws_s3_bucket.website.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "AllowCloudFrontServicePrincipal"
        Effect = "Allow"
        Principal = {
          Service = "cloudfront.amazonaws.com"
        }
        Action   = "s3:GetObject"
        Resource = "${aws_s3_bucket.website.arn}/*"
        Condition = {
          StringEquals = {
            "AWS:SourceArn" = aws_cloudfront_distribution.website.arn
          }
        }
      }
    ]
  })
}

# ============================================================================
# ENHANCED CLOUDWATCH ALARMS
# ============================================================================

resource "aws_cloudwatch_metric_alarm" "high_4xx_error_rate" {
  alarm_name          = "${var.project_name}-high-4xx-error-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "4xxErrorRate"
  namespace           = "AWS/CloudFront"
  period              = "300"
  statistic           = "Average"
  threshold           = "5"
  alarm_description   = "This metric monitors 4xx error rate"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    DistributionId = aws_cloudfront_distribution.website.id
  }

  tags = {
    Name        = "${var.project_name}-4xx-alarm"
    Environment = var.environment
  }
}

resource "aws_cloudwatch_metric_alarm" "high_5xx_error_rate" {
  alarm_name          = "${var.project_name}-high-5xx-error-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "5xxErrorRate"
  namespace           = "AWS/CloudFront"
  period              = "300"
  statistic           = "Average"
  threshold           = "1"
  alarm_description   = "This metric monitors 5xx error rate"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  ok_actions          = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    DistributionId = aws_cloudfront_distribution.website.id
  }

  tags = {
    Name        = "${var.project_name}-5xx-alarm"
    Environment = var.environment
  }
}

# Low cache hit ratio alarm
resource "aws_cloudwatch_metric_alarm" "low_cache_hit_rate" {
  alarm_name          = "${var.project_name}-low-cache-hit-rate"
  comparison_operator = "LessThanThreshold"
  evaluation_periods  = "3"
  metric_name         = "CacheHitRate"
  namespace           = "AWS/CloudFront"
  period              = "300"
  statistic           = "Average"
  threshold           = "80"
  alarm_description   = "This metric monitors CloudFront cache hit rate"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    DistributionId = aws_cloudfront_distribution.website.id
  }

  tags = {
    Name        = "${var.project_name}-cache-hit-alarm"
    Environment = var.environment
  }
}

# High request rate alarm (potential DDoS)
resource "aws_cloudwatch_metric_alarm" "high_request_rate" {
  alarm_name          = "${var.project_name}-high-request-rate"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "Requests"
  namespace           = "AWS/CloudFront"
  period              = "300"
  statistic           = "Sum"
  threshold           = "10000"
  alarm_description   = "This metric monitors for unusually high request rates"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    DistributionId = aws_cloudfront_distribution.website.id
  }

  tags = {
    Name        = "${var.project_name}-high-requests-alarm"
    Environment = var.environment
  }
}

# WAF blocked requests alarm
resource "aws_cloudwatch_metric_alarm" "waf_blocked_requests" {
  alarm_name          = "${var.project_name}-waf-blocked-requests"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = "2"
  metric_name         = "BlockedRequests"
  namespace           = "AWS/WAFV2"
  period              = "300"
  statistic           = "Sum"
  threshold           = "100"
  alarm_description   = "This metric monitors WAF blocked requests"
  alarm_actions       = [aws_sns_topic.alerts.arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    WebACL = aws_wafv2_web_acl.website.name
    Rule   = "ALL"
    Region = "CloudFront"
  }

  tags = {
    Name        = "${var.project_name}-waf-blocked-alarm"
    Environment = var.environment
  }
}

# ============================================================================
# SNS TOPIC FOR ALERTS
# ============================================================================

resource "aws_sns_topic" "alerts" {
  name = "${var.project_name}-${var.environment}-alerts"

  tags = {
    Name        = "${var.project_name}-alerts"
    Environment = var.environment
  }
}

# ============================================================================
# ENHANCED CLOUDWATCH DASHBOARD
# ============================================================================

resource "aws_cloudwatch_dashboard" "website" {
  dashboard_name = "${var.project_name}-${var.environment}-dashboard"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/CloudFront", "Requests", "DistributionId", aws_cloudfront_distribution.website.id, { "stat": "Sum" }],
            [".", "BytesDownloaded", ".", ".", { "stat": "Sum" }],
            [".", "BytesUploaded", ".", ".", { "stat": "Sum" }]
          ]
          view    = "timeSeries"
          stacked = false
          region  = data.aws_region.current.name
          title   = "CloudFront Traffic Metrics"
          period  = 300
          yAxis = {
            left = {
              min = 0
            }
          }
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/CloudFront", "4xxErrorRate", "DistributionId", aws_cloudfront_distribution.website.id],
            [".", "5xxErrorRate", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = data.aws_region.current.name
          title   = "Error Rates (%)"
          period  = 300
          yAxis = {
            left = {
              min = 0
              max = 10
            }
          }
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/CloudFront", "CacheHitRate", "DistributionId", aws_cloudfront_distribution.website.id],
            [".", "OriginLatency", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = data.aws_region.current.name
          title   = "Cache Performance"
          period  = 300
          yAxis = {
            left = {
              min = 0
            }
          }
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 6
        width  = 12
        height = 6

        properties = {
          metrics = [
            ["AWS/WAFV2", "AllowedRequests", "WebACL", aws_wafv2_web_acl.website.name, "Rule", "ALL", "Region", "CloudFront"],
            [".", "BlockedRequests", ".", ".", ".", ".", ".", "."]
          ]
          view    = "timeSeries"
          stacked = false
          region  = data.aws_region.current.name
          title   = "WAF Request Filtering"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 12
        width  = 8
        height = 6

        properties = {
          metrics = [
            ["AWS/WAFV2", "BlockedRequests", "WebACL", aws_wafv2_web_acl.website.name, "Rule", "RateLimitRule", "Region", "CloudFront"],
            [".", ".", ".", ".", ".", "AWSManagedRulesCommonRuleSet", ".", "."],
            [".", ".", ".", ".", ".", "AWSManagedRulesKnownBadInputsRuleSet", ".", "."],
            [".", ".", ".", ".", ".", "GeoBlockingRule", ".", "."]
          ]
          view    = "timeSeries"
          stacked = true
          region  = data.aws_region.current.name
          title   = "WAF Rules - Blocked Requests"
          period  = 300
        }
      },
      {
        type   = "metric"
        x      = 8
        y      = 12
        width  = 8
        height = 6

        properties = {
          view    = "singleValue"
          metrics = [
            ["AWS/CloudFront", "Requests", "DistributionId", aws_cloudfront_distribution.website.id, { "stat": "Sum" }],
            [".", "4xxErrorRate", ".", ".", { "stat": "Average" }],
            [".", "5xxErrorRate", ".", ".", { "stat": "Average" }],
            [".", "CacheHitRate", ".", ".", { "stat": "Average" }]
          ]
          region = data.aws_region.current.name
          title  = "Current Status"
          period = 300
        }
      },
      {
        type   = "metric"
        x      = 16
        y      = 12
        width  = 8
        height = 6

        properties = {
          view    = "singleValue"
          metrics = [
            ["AWS/WAFV2", "AllowedRequests", "WebACL", aws_wafv2_web_acl.website.name, "Rule", "ALL", "Region", "CloudFront", { "stat": "Sum" }],
            [".", "BlockedRequests", ".", ".", ".", ".", ".", ".", { "stat": "Sum" }]
          ]
          region = data.aws_region.current.name
          title  = "WAF Summary (24h)"
          period = 86400
        }
      },
      {
        type   = "log"
        x      = 0
        y      = 18
        width  = 24
        height = 6

        properties = {
          query   = "SOURCE '${aws_cloudwatch_log_group.waf_logs.name}' | fields @timestamp, action, terminatingRuleId, httpRequest.clientIp, httpRequest.country\n| filter action = \"BLOCK\"\n| stats count() by httpRequest.country\n| sort count desc\n| limit 10"
          region  = data.aws_region.current.name
          title   = "Top Blocked Countries (Last 24h)"
          view    = "table"
        }
      }
    ]
  })
}

# ============================================================================
# OUTPUTS
# ============================================================================

output "cloudfront_distribution_id" {
  description = "ID of the CloudFront distribution"
  value       = aws_cloudfront_distribution.website.id
}

output "cloudfront_domain_name" {
  description = "Domain name of the CloudFront distribution"
  value       = aws_cloudfront_distribution.website.domain_name
}

output "s3_bucket_name" {
  description = "Name of the S3 bucket"
  value       = aws_s3_bucket.website.bucket
}

output "waf_web_acl_arn" {
  description = "ARN of the WAF Web ACL"
  value       = aws_wafv2_web_acl.website.arn
}

output "ssl_certificate_arn" {
  description = "ARN of the SSL certificate"
  value       = aws_acm_certificate.website.arn
}

output "logs_bucket_name" {
  description = "Name of the logs S3 bucket"
  value       = aws_s3_bucket.logs.bucket
}

output "sns_topic_arn" {
  description = "ARN of the SNS topic for alerts"
  value       = aws_sns_topic.alerts.arn
}

output "dashboard_url" {
  description = "URL of the CloudWatch dashboard"
  value       = "https://${data.aws_region.current.name}.console.aws.amazon.com/cloudwatch/home?region=${data.aws_region.current.name}#dashboards:name=${aws_cloudwatch_dashboard.website.dashboard_name}"
}
