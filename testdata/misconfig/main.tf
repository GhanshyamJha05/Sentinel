resource "aws_security_group" "web" {
  name = "web"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket" "logs" {
  bucket = "example-logs"
  acl    = "public-read"
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket                  = aws_s3_bucket.logs.id
  block_public_acls       = false
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_instance" "app" {
  ami           = "ami-123"
  instance_type = "t3.micro"

  metadata_options {
    http_tokens = "optional"
  }
}

variable "db_password" {
  type = string
}

resource "aws_db_instance" "main" {
  password = "SuperSecretDBPass1"
}
