# ============================================================================
# TERRAFORM VARIABLES CONFIGURATION
# ============================================================================

# Domain configuration
use_custom_domain = false
domain_name       = ""
# If you want to use your own domain later, change to:
# use_custom_domain = true
# domain_name = "yourdomain.com"

# Environment settings
environment  = "production"
project_name = "secure-website"

# Security settings - Countries allowed to access the website
# Use ISO 3166-1 alpha-2 country codes
allowed_countries = []

# Example for different environments:
# For staging:
# environment = "staging"
# allowed_countries = ["US", "CA"]

# For development:
# environment = "development"
# allowed_countries = ["US"]
