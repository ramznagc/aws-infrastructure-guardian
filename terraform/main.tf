
terraform {
  required_version = ">= 1.6.0"
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "AWS Infrastructure Guardian"
      Environment = var.environment
      ManagedBy   = "Terraform"
    }
  }
}
