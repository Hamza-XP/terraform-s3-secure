#!/bin/bash

# ============================================================================
# TERRAFORM DEPLOYMENT SCRIPT
# Secure Website Infrastructure Deployment
# ============================================================================

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to check if required tools are installed
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    if ! command -v terraform &> /dev/null; then
        print_error "Terraform is not installed. Please install Terraform first."
        exit 1
    fi
    
    if ! command -v aws &> /dev/null; then
        print_error "AWS CLI is not installed. Please install AWS CLI first."
        exit 1
    fi
    
    # Check AWS credentials
    if ! aws sts get-caller-identity &> /dev/null; then
        print_error "AWS credentials not configured. Please run 'aws configure' first."
        exit 1
    fi
    
    print_success "Prerequisites check passed"
}

# Function to validate terraform files
validate_terraform() {
    print_status "Validating Terraform configuration..."
    
    if ! terraform validate; then
        print_error "Terraform validation failed"
        exit 1
    fi
    
    print_success "Terraform validation passed"
}

# Function to check if tfvars file exists
check_tfvars() {
    if [ ! -f "terraform.tfvars" ]; then
        print_warning "terraform.tfvars not found"
        print_status "Creating terraform.tfvars from example..."
        
        if [ -f "terraform.tfvars.example" ]; then
            cp terraform.tfvars.example terraform.tfvars
            print_warning "Please edit terraform.tfvars with your specific values before continuing"
            print_status "Required changes:"
            echo "  - Set your domain_name"
            echo "  - Adjust allowed_countries as needed"
            echo "  - Modify project_name if desired"
            read -p "Press Enter after updating terraform.tfvars to continue..."
        else
            print_error "terraform.tfvars.example not found"
            exit 1
        fi
    fi
}

# Function to initialize Terraform
terraform_init() {
    print_status "Initializing Terraform..."
    
    if ! terraform init; then
        print_error "Terraform initialization failed"
        exit 1
    fi
    
    print_success "Terraform initialized successfully"
}

# Function to plan deployment
terraform_plan() {
    print_status "Creating Terraform execution plan..."
    
    if ! terraform plan -out=tfplan; then
        print_error "Terraform planning failed"
        exit 1
    fi
    
    print_success "Terraform plan created successfully"
    print_warning "Please review the plan above before applying"
}

# Function to apply changes
terraform_apply() {
    print_status "Applying Terraform changes..."
    
    if ! terraform apply tfplan; then
        print_error "Terraform apply failed"
        exit 1
    fi
    
    print_success "Infrastructure deployed successfully!"
}

# Function to upload website files
upload_website() {
    print_status "Uploading website files to S3..."
    
    # Get S3 bucket name from Terraform output
    BUCKET_NAME=$(terraform output -raw s3_bucket_name)
    
    if [ -z "$BUCKET_NAME" ]; then
        print_error "Could not get S3 bucket name from Terraform output"
        exit 1
    fi
    
    # Upload index.html
    if [ -f "index.html" ]; then
        aws s3 cp index.html s3://$BUCKET_NAME/ --content-type "text/html"
        print_success "Uploaded index.html"
    else
        print_warning "index.html not found in current directory"
    fi
    
    # Upload PNG files
    for file in *.png; do
        if [ -f "$file" ]; then
            aws s3 cp "$file" s3://$BUCKET_NAME/ --content-type "image/png"
            print_success "Uploaded $file"
        fi
    done
    
    print_success "Website files uploaded successfully"
}

# Function to invalidate CloudFront cache
invalidate_cache() {
    print_status "Invalidating CloudFront cache..."
    
    DISTRIBUTION_ID=$(terraform output -raw cloudfront_distribution_id)
    
    if [ -z "$DISTRIBUTION_ID" ]; then
        print_error "Could not get CloudFront distribution ID"
        exit 1
    fi
    
    aws cloudfront create-invalidation --distribution-id $DISTRIBUTION_ID --paths "/*"
    print_success "CloudFront cache invalidation initiated"
}

# Function to display deployment summary
show_summary() {
    print_success "=== DEPLOYMENT SUMMARY ==="
    
    echo ""
    echo "Infrastructure Details:"
    echo "  S3 Bucket: $(terraform output -raw s3_bucket_name)"
    echo "  CloudFront Distribution: $(terraform output -raw cloudfront_distribution_id)"
    echo "  CloudFront Domain: $(terraform output -raw cloudfront_domain_name)"
    echo "  WAF Web ACL: $(terraform output -raw waf_web_acl_arn)"
    echo "  SSL Certificate: $(terraform output -raw ssl_certificate_arn)"
    echo "  Logs Bucket: $(terraform output -raw logs_bucket_name)"
    echo "  SNS Topic: $(terraform output -raw sns_topic_arn)"
    echo ""
    echo "Monitoring:"
    echo "  Dashboard: $(terraform output -raw dashboard_url)"
    echo ""
    echo "Next Steps:"
    echo "  1. Configure DNS records to point to CloudFront distribution"
    echo "  2. Complete SSL certificate validation (if using DNS validation)"
    echo "  3. Configure SNS topic subscription for alerts"
    echo "  4. Test website accessibility and security features"
    echo ""
    print_success "Deployment completed successfully!"
}

# Function to cleanup on error
cleanup() {
    if [ -f "tfplan" ]; then
        rm -f tfplan
    fi
}

# Trap cleanup function on exit
trap cleanup EXIT

# Main execution flow
main() {
    print_status "Starting infrastructure deployment..."
    
    check_prerequisites
    check_tfvars
    terraform_init
    validate_terraform
    terraform_plan
    
    # Ask for confirmation before applying
    echo ""
    read -p "Do you want to apply these changes? (y/N): " -n 1 -r
    echo ""
    
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        terraform_apply
        upload_website
        invalidate_cache
        show_summary
    else
        print_status "Deployment cancelled by user"
        exit 0
    fi
}

# Check if script is being sourced or executed
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    main "$@"
fi