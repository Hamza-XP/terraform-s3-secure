# ============================================================================
# TERRAFORM VARIABLES CONFIGURATION
# Copy this file to terraform.tfvars and customize the values
# ============================================================================

# Domain configuration
domain_name = "yourdomain.com"

# Environment settings
environment  = "production"
project_name = "secure-website"

# Security settings - Countries allowed to access the website
# Use ISO 3166-1 alpha-2 country codes
allowed_countries = [
  "US", # United States
  "CA", # Canada
  "GB", # United Kingdom
  "DE", # Germany
  "FR", # France
  "AU", # Australia
  "JP", # Japan
  "SG", # Singapore
]

# Example for different environments:
# For staging:
# environment = "staging"
# allowed_countries = ["US", "CA"]

# For development:
# environment = "development"
# allowed_countries = ["US"]
