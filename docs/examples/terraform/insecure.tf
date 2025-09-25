### docs/examples/terraform/insecure.tf
```hcl
# Example Terraform file with security issues
# This file is intentionally insecure for testing purposes

# Insecure S3 bucket with public access
resource "aws_s3_bucket" "insecure_bucket" {
  bucket = "my-insecure-bucket-12345"
  acl    = "public-read"  # SECURITY ISSUE: Public access

  versioning {
    enabled = false  # SECURITY ISSUE: No versioning
  }
}

# Security group allowing access from anywhere
resource "aws_security_group" "insecure_sg" {
  name_prefix = "insecure-sg"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # SECURITY ISSUE: SSH open to world
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # SECURITY ISSUE: RDP open to world
  }
}

# RDS instance with public access
resource "aws_db_instance" "insecure_db" {
  identifier           = "insecure-database"
  engine              = "mysql"
  instance_class      = "db.t3.micro"
  allocated_storage   = 20
  db_name             = "testdb"
  username            = "admin"
  password            = "password123"  # SECURITY ISSUE: Hardcoded password
  publicly_accessible = true          # SECURITY ISSUE: Public access
  skip_final_snapshot = true
}

# IAM policy with wildcard permissions
resource "aws_iam_policy" "insecure_policy" {
  name = "insecure-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"                    # SECURITY ISSUE: Wildcard permissions
        Resource = "*"                    # SECURITY ISSUE: All resources
      }
    ]
  })
}

# EC2 instance without encryption
resource "aws_instance" "insecure_instance" {
  ami           = "ami-0abcdef1234567890"
  instance_class = "t3.micro"
  
  root_block_device {
    encrypted = false  # SECURITY ISSUE: Unencrypted storage
  }
  
  metadata_options {
    http_tokens = "optional"  # SECURITY ISSUE: IMDSv1 allowed
  }
}