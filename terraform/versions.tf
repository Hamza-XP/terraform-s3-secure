# ============================================================================
# TERRAFORM VERSION CONSTRAINTS
# Ensures compatibility and reproducible deployments
# ============================================================================

terraform {
  required_version = ">= 1.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.1"
    }
  }

  # Uncomment and configure for remote state storage
  # backend "s3" {
  #   bucket         = "your-terraform-state-bucket"
  #   key            = "secure-website/terraform.tfstate"
  #   region         = "us-east-1"
  #   encrypt        = true
  #   dynamodb_table = "terraform-state-locks"
  # }
}

# ============================================================================
# PROVIDER CONFIGURATION
# ============================================================================

provider "aws" {
  region = "us-east-1" # Required for CloudFront and ACM certificates

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
      Owner       = "Infrastructure Team"
      CreatedAt   = timestamp()
    }
  }
}

provider "aws" {
  alias  = "virginia"
  region = "us-east-1" # For CloudFront and ACM (must be us-east-1)

  default_tags {
    tags = {
      Project     = var.project_name
      Environment = var.environment
      ManagedBy   = "Terraform"
      Owner       = "Infrastructure Team"
      CreatedAt   = timestamp()
    }
  }
}

provider "random" {
  # No configuration needed
}
