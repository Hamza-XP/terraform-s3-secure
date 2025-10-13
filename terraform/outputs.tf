# ============================================================================
# TERRAFORM OUTPUTS
# All important resource identifiers and endpoints
# ============================================================================

# Infrastructure Identifiers
output "cloudfront_distribution_id" {
  description = "ID of the CloudFront distribution"
  value       = aws_cloudfront_distribution.website.id
}

output "cloudfront_domain_name" {
  description = "Domain name of the CloudFront distribution"
  value       = aws_cloudfront_distribution.website.domain_name
}

output "cloudfront_arn" {
  description = "ARN of the CloudFront distribution"
  value       = aws_cloudfront_distribution.website.arn
}

output "s3_bucket_name" {
  description = "Name of the S3 bucket hosting the website"
  value       = aws_s3_bucket.website.bucket
}

output "s3_bucket_arn" {
  description = "ARN of the S3 bucket"
  value       = aws_s3_bucket.website.arn
}

output "s3_bucket_domain_name" {
  description = "Regional domain name of the S3 bucket"
  value       = aws_s3_bucket.website.bucket_regional_domain_name
}

# Security Resources
output "waf_web_acl_id" {
  description = "ID of the WAF Web ACL"
  value       = aws_wafv2_web_acl.website.id
}

output "waf_web_acl_arn" {
  description = "ARN of the WAF Web ACL"
  value       = aws_wafv2_web_acl.website.arn
}

# COMMENTED OUT domain validation options output
/*
output "ssl_certificate_arn" {
  description = "ARN of the SSL certificate"
  value       = aws_acm_certificate.website.arn
}
*/
# CHANGED TO:
output "ssl_certificate_arn" {
  description = "ARN of the SSL certificate (only if using custom domain)"
  value       = "Using CloudFront default certificate"
}

output "ssl_certificate_domain_validation_options" {
  description = "Domain validation options for the SSL certificate"
  value       = aws_acm_certificate.website.domain_validation_options
  sensitive   = false
}

# Logging Resources
output "logs_bucket_name" {
  description = "Name of the logs S3 bucket"
  value       = aws_s3_bucket.logs.bucket
}

output "logs_bucket_arn" {
  description = "ARN of the logs S3 bucket"
  value       = aws_s3_bucket.logs.arn
}

# # Monitoring Resources
# output "sns_topic_arn" {
#   description = "ARN of the SNS topic for alerts"
#   value       = aws_sns_topic.alerts.arn
# }

output "cloudwatch_dashboard_name" {
  description = "Name of the CloudWatch dashboard"
  value       = aws_cloudwatch_dashboard.website.dashboard_name
}

output "dashboard_url" {
  description = "URL of the CloudWatch dashboard"
  value       = "https://${data.aws_region.current.name}.console.aws.amazon.com/cloudwatch/home?region=${data.aws_region.current.name}#dashboards:name=${aws_cloudwatch_dashboard.website.dashboard_name}"
}

# Alarm ARNs
output "high_4xx_alarm_arn" {
  description = "ARN of the high 4xx error rate alarm"
  value       = aws_cloudwatch_metric_alarm.high_4xx_error_rate.arn
}

output "high_5xx_alarm_arn" {
  description = "ARN of the high 5xx error rate alarm"
  value       = aws_cloudwatch_metric_alarm.high_5xx_error_rate.arn
}

# COMMENTED OUT:
# Configuration Values
# output "website_url" {
#   description = "Main website URL"
#   value       = "https://${var.domain_name}"
# }
# CHANGED TO:
output "website_url" {
  description = "Main website URL"
  value       = "https://${aws_cloudfront_distribution.website.domain_name}"
}

output "www_website_url" {
  description = "WWW website URL"
  value       = "https://www.${var.domain_name}"
}

output "cloudfront_url" {
  description = "CloudFront distribution URL"
  value       = "https://${aws_cloudfront_distribution.website.domain_name}"
}

# Project Information
output "project_info" {
  description = "Project configuration summary"
  value = {
    project_name      = var.project_name
    environment       = var.environment
    # domain_name       = var.domain_name
    # CHANGED:
    domain_name = var.use_custom_domain ? var.domain_name : "Using CloudFront domain"
    allowed_countries = var.allowed_countries
    aws_region        = data.aws_region.current.name
    account_id        = data.aws_caller_identity.current.account_id
  }
}

# COMMENTED OUT: Full DNS configuration object
# # DNS Configuration Help
# output "dns_configuration_help" {
#   description = "DNS records that need to be configured"
#   value = {
#     root_domain = {
#       type   = "A"
#       name   = var.domain_name
#       value  = "ALIAS to ${aws_cloudfront_distribution.website.domain_name}"
#       note   = "Use ALIAS record for root domain (Route 53) or A record with CloudFront IP"
#     }
#     www_subdomain = {
#       type  = "CNAME"
#       name  = "www.${var.domain_name}"
#       value = aws_cloudfront_distribution.website.domain_name
#       note  = "Standard CNAME record pointing to CloudFront"
#     }
#     ssl_validation = {
#       note = "Check domain_validation_options output for SSL certificate validation records"
#     }
#   }
# }
# CHANGED TO:
output "dns_configuration_help" {
  description = "DNS records that need to be configured (only applicable if using custom domain)"
  value       = "No DNS configuration needed - using CloudFront URL"
}

# Security Configuration Summary
output "security_summary" {
  description = "Security features enabled"
  value = {
    waf_enabled           = true
    rate_limiting         = "2000 requests per 5 minutes per IP"
    geo_blocking          = "Enabled for countries: ${join(", ", var.allowed_countries)}"
    https_only            = true
    security_headers      = "HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy"
    s3_encryption         = "AES256"
    cloudfront_oac        = "Enabled - prevents direct S3 access"
    log_retention         = "90 days"
  }
}

# Cost Estimation
output "cost_estimation" {
  description = "Estimated monthly costs (approximate)"
  value = {
    s3_storage          = "$0.023 per GB stored"
    s3_requests         = "$0.0004 per 1,000 GET requests"
    cloudfront_requests = "$0.0075 per 10,000 HTTP requests"
    cloudfront_data     = "$0.085 per GB transferred"
    waf_web_acl         = "$1.00 per month + $0.60 per million requests"
    cloudwatch_alarms   = "$0.10 per alarm per month"
    ssl_certificate     = "Free with ACM"
    note                = "Actual costs depend on usage. Monitor via AWS Cost Explorer"
  }
}

# Monitoring URLs
output "monitoring_urls" {
  description = "Important monitoring and management URLs"
  value = {
    cloudwatch_dashboard = "https://${data.aws_region.current.name}.console.aws.amazon.com/cloudwatch/home?region=${data.aws_region.current.name}#dashboards:name=${aws_cloudwatch_dashboard.website.dashboard_name}"
    cloudfront_console   = "https://console.aws.amazon.com/cloudfront/v3/home#/distributions/${aws_cloudfront_distribution.website.id}"
    waf_console          = "https://${data.aws_region.current.name}.console.aws.amazon.com/wafv2/homev2/web-acl/${aws_wafv2_web_acl.website.name}/${aws_wafv2_web_acl.website.id}/overview?region=global"
    s3_console           = "https://s3.console.aws.amazon.com/s3/buckets/${aws_s3_bucket.website.bucket}"
    # COMMENTED OUT:
    # acm_console          = "https://${data.aws_region.current.name}.console.aws.amazon.com/acm/home?region=${data.aws_region.current.name}#/certificates/${replace(aws_acm_certificate.website.arn, "arn:aws:acm:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:certificate/", "")}"
  }
}

# Next Steps
output "next_steps" {
  description = "Post-deployment steps to complete setup"
  value = [
    "0, Your website is accessible at: https://${aws_cloudfront_distribution.website.domain_name}",
    "1. Configure DNS records using the dns_configuration_help output",
    "2. Validate SSL certificate through DNS or email validation",
    "3. Upload your website files to S3 bucket: ${aws_s3_bucket.website.bucket}",
    # "4. Subscribe to SNS topic ${aws_sns_topic.alerts.arn} for alerts",
    "4. Configure alert notifications (SNS disabled for now)",
    "5. Test website accessibility and security features",
    "6. Configure CloudWatch alarm notifications",
    "7. Review and customize WAF rules if needed",
    "8. Set up log analysis with AWS Athena (optional)",
    "9. Configure backup and disaster recovery procedures",
    "10. Document your deployment and maintenance procedures"
  ]
}
