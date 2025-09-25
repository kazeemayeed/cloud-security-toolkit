# Example secure Terraform configuration
# This shows best practices for cloud security

# Secure S3 bucket configuration
resource "aws_s3_bucket" "secure_bucket" {
  bucket = "my-secure-bucket-12345"
}

resource "aws_s3_bucket_acl" "secure_bucket_acl" {
  bucket = aws_s3_bucket.secure_bucket.id
  acl    = "private"
}

resource "aws_s3_bucket_versioning" "secure_bucket_versioning" {
  bucket = aws_s3_bucket.secure_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "secure_bucket_encryption" {
  bucket = aws_s3_bucket.secure_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "secure_bucket_pab" {
  bucket = aws_s3_bucket.secure_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Secure security group with restricted access
resource "aws_security_group" "secure_sg" {
  name_prefix = "secure-sg"

  # Allow SSH only from specific IP range
  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]  # Restricted to private networks
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# Secure RDS instance
resource "aws_db_instance" "secure_db" {
  identifier     = "secure-database"
  engine         = "mysql"
  engine_version = "8.0"
  instance_class = "db.t3.micro"
  
  allocated_storage     = 20
  max_allocated_storage = 100
  storage_encrypted     = true
  
  db_name  = "securedb"
  username = "dbadmin"
  password = random_password.db_password.result
  
  publicly_accessible = false
  
  vpc_security_group_ids = [aws_security_group.db_sg.id]
  db_subnet_group_name   = aws_db_subnet_group.secure_subnet_group.name
  
  backup_retention_period = 7
  backup_window          = "03:00-04:00"
  maintenance_window     = "sun:04:00-sun:05:00"
  
  skip_final_snapshot = false
  final_snapshot_identifier = "secure-db-final-snapshot"
  
  enabled_cloudwatch_logs_exports = ["error", "general", "slow_query"]
}

resource "random_password" "db_password" {
  length  = 16
  special = true
}

# IAM policy with least privilege
resource "aws_iam_policy" "secure_policy" {
  name = "secure-policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject"
        ]
        Resource = "${aws_s3_bucket.secure_bucket.arn}/*"
      }
    ]
  })
}

# Secure EC2 instance
resource "aws_instance" "secure_instance" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.micro"
  
  vpc_security_group_ids = [aws_security_group.secure_sg.id]
  subnet_id             = aws_subnet.private_subnet.id
  
  root_block_device {
    encrypted   = true
    volume_type = "gp3"
    volume_size = 20
  }
  
  metadata_options {
    http_tokens                 = "required"  # Enforce IMDSv2
    http_put_response_hop_limit = 1
    http_endpoint              = "enabled"
  }
  
  monitoring = true
  
  tags = {
    Name        = "secure-instance"
    Environment = "production"
  }
}