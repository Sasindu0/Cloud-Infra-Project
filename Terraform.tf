terraform {

  backend "s3" {
    bucket  = "cloud-project-react-bkt"
    key     = "tfstate-key/terraform.tfstate"
    region  = "us-east-1"
    encrypt = true
  }

  required_version = ">=0.13.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">=3.0"
    }
  }
}

provider "aws" {
  region = "us-east-1"
}

################ s3 Bucket Configurations #######################

resource "aws_s3_bucket" "reactapp_bucket" {
  bucket        = "cloud-project-react-bkt"
  force_destroy = true
}

resource "aws_s3_bucket_versioning" "reactapp_bucket_versioning" {
  bucket = aws_s3_bucket.reactapp_bucket.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "reactapp_bucket_crypto_conf" {
  bucket = aws_s3_bucket.reactapp_bucket.bucket
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "bucket_public_access_block" {
  bucket = aws_s3_bucket.reactapp_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_website_configuration" "react_website_configuration" {
  bucket = aws_s3_bucket.reactapp_bucket.bucket

  index_document {
    suffix = "index.html"
  }
  error_document {
    key = "index.html"
  }
}

################ EC2 instance Configurations #######################

resource "tls_private_key" "rsa_4096" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "Flask_Web_Server_Keys" {
  key_name   = "Flask_Web_Server_Keys"
  public_key = tls_private_key.rsa_4096.public_key_openssh
}

resource "local_file" "flask_private_key" {
  content  = tls_private_key.rsa_4096.private_key_pem
  filename = "Flask_Web_Server_Keys.pem"
}

resource "aws_security_group" "allow_traffic" {
  name        = "allow_traffic"
  description = "Allow SSH, HTTP, and HTTPS traffic"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "Flask_Web_Server" {
  ami                    = "ami-0c7217cdde317cfec" # Ubuntu AMI
  instance_type          = "t2.micro"
  vpc_security_group_ids = [aws_security_group.allow_traffic.id]
  key_name               = aws_key_pair.Flask_Web_Server_Keys.key_name

  tags = {
  name = "Flask-Web-Server" }
}

################ Cloud-Front Configurations #######################

resource "aws_cloudfront_origin_access_identity" "my_origin_access_identity" {
  comment = "origin access identity for the React App"
}

data "aws_cloudfront_cache_policy" "CachingDisabled" {
  name = "Managed-CachingDisabled"
  
}

data "aws_cloudfront_cache_policy" "CachingOptimized" {
  name = "CachingOptimized"
  
}

resource "aws_cloudfront_distribution" "my_distribution" {

  depends_on = [
  aws_s3_bucket.reactapp_bucket]

  origin {
    domain_name = aws_s3_bucket.reactapp_bucket.bucket_regional_domain_name
    origin_id   = "reactapp-s3-origin"

    s3_origin_config {
      origin_access_identity = aws_cloudfront_origin_access_identity.my_origin_access_identity.cloudfront_access_identity_path
    }
  }

  origin {
    domain_name = aws_instance.Flask_Web_Server.public_dns
    origin_id   = "flask-web-server-origin"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "http-only"
      origin_ssl_protocols   = ["TLSv1.2"]
    }
  }

  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "index.html"

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  default_cache_behavior {
    allowed_methods  = ["HEAD", "DELETE", "POST", "GET", "OPTIONS", "PUT", "PATCH"]
    target_origin_id = "reactapp-s3-origin"
    cached_methods   = ["GET", "HEAD"]
    compress         = true
    cache_policy_id = data.aws_cloudfront_cache_policy.CachingOptimized.id

    /* forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    } */

    viewer_protocol_policy = "redirect-to-https"
    /* min_ttl                = 0
    default_ttl            = 0
    max_ttl                = 0 */
  }

  ordered_cache_behavior {
    path_pattern     = "/api/*"
    allowed_methods  = ["GET", "HEAD", "POST", "PUT", "PATCH", "OPTIONS", "DELETE"]
    cached_methods   = ["GET", "HEAD"]
    target_origin_id = "flask-web-server-origin"
    compress         = true
    cache_policy_id = data.aws_cloudfront_cache_policy.CachingDisabled.id

    /* forwarded_values {
      query_string = false

      cookies {
        forward = "none"
      }
    } */

    viewer_protocol_policy = "redirect-to-https"
    /* min_ttl                = 0
    default_ttl            = 0
    max_ttl                = 0 */
  }

  custom_error_response {
    error_caching_min_ttl = 0
    error_code            = 404
    response_code         = 200
    response_page_path    = "/index.html"
  }
}

resource "aws_s3_bucket_policy" "public_read_access" {
  bucket = aws_s3_bucket.reactapp_bucket.id
  policy = data.aws_iam_policy_document.public_read_access.json
}

data "aws_iam_policy_document" "public_read_access" {
  statement {
    principals {
      type        = "AWS"
      identifiers = [aws_cloudfront_origin_access_identity.my_origin_access_identity.iam_arn]
    }

    actions = [
      "s3:GetObject",
      "s3:ListBucket"
    ]

    resources = [
      aws_s3_bucket.reactapp_bucket.arn,
      "${aws_s3_bucket.reactapp_bucket.arn}/*",
    ]

  }
}