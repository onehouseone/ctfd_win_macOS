provider "aws" {
  region = "eu-north-1"
}

# Create lambda_src directory (cross-platform)
resource "null_resource" "create_lambda_dir" {
  provisioner "local-exec" {
    command     = "mkdir -p ${path.module}/lambda_src"
    interpreter = ["/bin/bash", "-c"] # For macOS/Linux
    
    # Windows alternative (uncomment if needed)
    # command = "if not exist ${path.module}\\lambda_src mkdir ${path.module}\\lambda_src"
    # interpreter = ["cmd", "/c"]
  }
}

# --- Local Files for Lambda ---
resource "local_file" "lambda_function" {
  filename = "${path.module}/lambda_src/lambda_function.py"
  content = <<-EOF
import boto3
import requests
import os
import json
from challenge_parser import parse_challenge
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

def lambda_handler(event, context):
    s3 = boto3.client('s3')
    ctfd_url = os.environ['CTFD_URL']
    
    try:
        session = requests.Session()
        
        for record in event['Records']:
            bucket = record['s3']['bucket']['name']
            key = record['s3']['object']['key']
            
            obj = s3.get_object(Bucket=bucket, Key=key)
            file_content = obj['Body'].read().decode('utf-8')
            
            if key.endswith('.yaml') or key.endswith('.yml'):
                challenge = parse_challenge(file_content)
                create_web_challenge(session, ctfd_url, challenge)
            elif key.endswith('.json'):
                challenge = json.loads(file_content)
                create_hardware_challenge(session, ctfd_url, challenge)
                
        return {'statusCode': 200, 'body': 'Challenges synced successfully'}
        
    except Exception as e:
        print(f"Error: {str(e)}")
        return {'statusCode': 500, 'body': str(e)}

def create_web_challenge(session, ctfd_url, challenge):
    api_url = f"{ctfd_url}/api/v1/challenges"
    response = session.post(
        api_url,
        json=challenge,
        headers={'Content-Type': 'application/json'},
        verify=False
    )
    response.raise_for_status()
    print(f"Created web challenge: {challenge['name']}")

def create_hardware_challenge(session, ctfd_url, challenge):
    api_url = f"{ctfd_url}/api/v1/challenges"
    payload = {
        "name": challenge["name"],
        "category": "Hardware",
        "description": challenge["description"],
        "value": challenge["points"],
        "state": "visible"
    }
    response = session.post(
        api_url,
        json=payload,
        headers={'Content-Type': 'application/json'},
        verify=False
    )
    response.raise_for_status()
    print(f"Created hardware challenge: {challenge['name']}")
  EOF

  depends_on = [null_resource.create_lambda_dir]
}

resource "local_file" "challenge_parser" {
  filename = "${path.module}/lambda_src/challenge_parser.py"
  content = <<-EOF
import yaml
import re

def parse_challenge(yaml_content):
    try:
        challenge = yaml.safe_load(yaml_content)
        
        required_fields = ['name', 'category', 'description', 'value']
        for field in required_fields:
            if field not in challenge:
                raise ValueError(f"Missing required field: {field}")
        
        challenge.setdefault('state', 'visible')
        challenge.setdefault('type', 'standard')
        
        if 'flags' in challenge:
            if not challenge['flags']:
                raise ValueError("At least one flag must be specified")
            
            for flag in challenge['flags']:
                if 'content' not in flag or not flag['content']:
                    raise ValueError("Flag content cannot be empty")
                flag.setdefault('type', 'static')
                flag.setdefault('data', 'case_insensitive')
        
        if 'description' in challenge:
            challenge['description'] = re.sub(r'<[^>]+>', '', challenge['description'])
        
        return challenge
        
    except yaml.YAMLError as e:
        raise ValueError(f"Invalid YAML: {str(e)}")
    except Exception as e:
        raise ValueError(f"Challenge validation failed: {str(e)}")
  EOF

  depends_on = [null_resource.create_lambda_dir]
}

resource "local_file" "requirements" {
  filename = "${path.module}/lambda_src/requirements.txt"
  content = <<-EOF
requests>=2.25.1
pyyaml>=5.4.1
boto3>=1.17.0
urllib3>=1.26.0
  EOF

  depends_on = [null_resource.create_lambda_dir]
}

# Cross-platform dependency installation
resource "null_resource" "install_dependencies" {
  triggers = {
    # Use file content hashes if files exist, otherwise use timestamp
    requirements = fileexists("${path.module}/lambda_src/requirements.txt") ? filemd5("${path.module}/lambda_src/requirements.txt") : timestamp()
    scripts      = fileexists("${path.module}/lambda_src/lambda_function.py") ? filemd5("${path.module}/lambda_src/lambda_function.py") : timestamp()
  }

  # Windows version
  #provisioner "local-exec" {
   # command     = "python -m pip install --no-user -r ${path.module}/lambda_src/requirements.txt -t ${path.module}/lambda_src/"
   # interpreter = ["cmd", "/c"]
  #}

  # macOS/Linux version
  provisioner "local-exec" {
    command     = "pip install --no-user -r ${path.module}/lambda_src/requirements.txt -t ${path.module}/lambda_src/"
    interpreter = ["/bin/bash", "-c"]
    
    # Only run on Unix-like systems
    when = destroy # This ensures it only runs when the Windows one doesn't
  }

  depends_on = [
    local_file.lambda_function,
    local_file.challenge_parser,
    local_file.requirements
  ]
}

# Create Lambda deployment package
data "archive_file" "lambda_zip" {
  type        = "zip"
  source_dir  = "${path.module}/lambda_src"
  output_path = "${path.module}/lambda_function.zip"
  depends_on  = [
    null_resource.install_dependencies
  ]
}

# --- Networking Configuration ---
resource "aws_vpc" "ctfd_vpc" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true
  tags = {
    Name = "CTFd-VPC"
  }
}

resource "aws_subnet" "private_subnet" {
  vpc_id            = aws_vpc.ctfd_vpc.id
  cidr_block        = "10.0.1.0/24"
  availability_zone = "eu-north-1a"
  tags = {
    Name = "CTFd-Private-Subnet"
  }
}

resource "aws_subnet" "public_subnet" {
  vpc_id                  = aws_vpc.ctfd_vpc.id
  cidr_block              = "10.0.2.0/24"
  availability_zone       = "eu-north-1a"
  map_public_ip_on_launch = true
  tags = {
    Name = "CTFd-Public-Subnet"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.ctfd_vpc.id
  tags = {
    Name = "CTFd-IGW"
  }
}

resource "aws_eip" "nat_eip" {
  domain = "vpc"
}

resource "aws_nat_gateway" "nat_gw" {
  allocation_id = aws_eip.nat_eip.id
  subnet_id     = aws_subnet.public_subnet.id
  depends_on    = [aws_internet_gateway.igw]
  tags = {
    Name = "CTFd-NAT-GW"
  }
}

resource "aws_route_table" "public_rt" {
  vpc_id = aws_vpc.ctfd_vpc.id
  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }
  tags = {
    Name = "CTFd-Public-RT"
  }
}

resource "aws_route_table" "private_rt" {
  vpc_id = aws_vpc.ctfd_vpc.id
  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat_gw.id
  }
  tags = {
    Name = "CTFd-Private-RT"
  }
}

resource "aws_route_table_association" "public_rta" {
  subnet_id      = aws_subnet.public_subnet.id
  route_table_id = aws_route_table.public_rt.id
}

resource "aws_route_table_association" "private_rta" {
  subnet_id      = aws_subnet.private_subnet.id
  route_table_id = aws_route_table.private_rt.id
}

# --- Security Groups ---
resource "aws_security_group" "lambda_sg" {
  name        = "lambda-ctfd-sg"
  description = "Security group for Lambda to access CTFd"
  vpc_id      = aws_vpc.ctfd_vpc.id

  egress {
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = [aws_subnet.public_subnet.cidr_block]
  }

  egress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "Lambda-CTFd-SG"
  }
}

resource "aws_security_group" "ctfd_sg" {
  name        = "ctfd-sg"
  description = "Security group for CTFd instance"
  vpc_id      = aws_vpc.ctfd_vpc.id

  ingress {
    from_port   = 8000
    to_port     = 8000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    from_port   = -1
    to_port     = -1
    protocol    = "icmp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "CTFd-SG"
  }
}

# --- CTFd EC2 Instance ---
resource "aws_instance" "ctfd_instance" {
  ami                    = "ami-0989fb15ce71ba39e"
  instance_type          = "t3.medium"
  subnet_id              = aws_subnet.public_subnet.id
  vpc_security_group_ids = [aws_security_group.ctfd_sg.id]
  key_name               = "testkey"
  associate_public_ip_address = true

  user_data = <<-EOF
              #!/bin/bash
              apt-get update -y
              apt-get install -y docker.io docker-compose
              systemctl enable docker
              systemctl start docker

              mkdir -p /opt/ctfd
              cd /opt/ctfd

              cat <<EOL > docker-compose.yml
              version: '3'
              services:
                ctfd:
                  image: ctfd/ctfd:latest
                  restart: always
                  ports:
                    - "8000:8000"
                  environment:
                    - UPLOAD_FOLDER=/var/uploads
                    - DATABASE_URL=mysql+pymysql://ctfd:ctfd@db/ctfd
                  volumes:
                    - ctfd-data:/var/uploads
                  depends_on:
                    - db

                db:
                  image: mariadb:10.11
                  restart: always
                  environment:
                    - MARIADB_ROOT_PASSWORD=ctfd
                    - MARIADB_USER=ctfd
                    - MARIADB_PASSWORD=ctfd
                    - MARIADB_DATABASE=ctfd
                  volumes:
                    - db-data:/var/lib/mysql

              volumes:
                ctfd-data:
                db-data:
              EOL

              docker-compose up -d
              EOF

  tags = {
    Name = "CTFd-Server"
  }
}

resource "aws_eip" "ctfd_eip" {
  domain   = "vpc"
  instance = aws_instance.ctfd_instance.id
}

# --- IAM Roles ---
resource "aws_iam_role" "lambda_exec" {
  name = "ctfd_lambda_exec_roles"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "lambda.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "lambda_vpc_access" {
  role       = aws_iam_role.lambda_exec.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

resource "aws_iam_role_policy" "lambda_s3_access" {
  name = "lambda_s3_access"
  role = aws_iam_role.lambda_exec.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow",
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ],
        Resource = [
          "${aws_s3_bucket.ctf_challenges.arn}",
          "${aws_s3_bucket.ctf_challenges.arn}/*"
        ]
      }
    ]
  })
}

# --- S3 Bucket ---
resource "random_id" "bucket_suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "ctf_challenges" {
  bucket = "ctf-challenges-bucket-${random_id.bucket_suffix.hex}"
}

# --- Lambda Function ---
resource "aws_lambda_function" "ctfd_sync_challenge" {
  function_name    = "ctfd_sync_challenge"
  handler          = "lambda_function.lambda_handler"
  runtime          = "python3.9"
  role             = aws_iam_role.lambda_exec.arn
  filename         = data.archive_file.lambda_zip.output_path
  source_code_hash = data.archive_file.lambda_zip.output_base64sha256
  timeout          = 300
  memory_size      = 256

  vpc_config {
    subnet_ids         = [aws_subnet.private_subnet.id]
    security_group_ids = [aws_security_group.lambda_sg.id]
  }

  environment {
    variables = {
      CTFD_URL = "http://${aws_instance.ctfd_instance.private_ip}:8000"
    }
  }

  depends_on = [
    aws_instance.ctfd_instance,
    data.archive_file.lambda_zip
  ]
}

resource "aws_lambda_permission" "allow_s3" {
  statement_id  = "AllowExecutionFromS3"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.ctfd_sync_challenge.arn
  principal     = "s3.amazonaws.com"
  source_arn    = aws_s3_bucket.ctf_challenges.arn
}

resource "aws_s3_bucket_notification" "bucket_notification" {
  bucket = aws_s3_bucket.ctf_challenges.id

  lambda_function {
    lambda_function_arn = aws_lambda_function.ctfd_sync_challenge.arn
    events              = ["s3:ObjectCreated:*"]
  }

  depends_on = [aws_lambda_permission.allow_s3]
}

# --- Outputs ---
output "ctfd_public_url" {
  value = "http://${aws_eip.ctfd_eip.public_ip}:8000"
}

output "ctfd_private_url" {
  value = "http://${aws_instance.ctfd_instance.private_ip}:8000"
}

output "s3_bucket_name" {
  value = aws_s3_bucket.ctf_challenges.bucket
}

output "lambda_function_name" {
  value = aws_lambda_function.ctfd_sync_challenge.function_name
}

output "ssh_access_command" {
  value = "ssh -i testkey.pem ubuntu@${aws_eip.ctfd_eip.public_ip}"
}

output "ctfd_status_check" {
  value = <<EOT
Check CTFd status with:
curl -v http://${aws_eip.ctfd_eip.public_ip}:8000
or
ssh -i testkey.pem ubuntu@${aws_eip.ctfd_eip.public_ip} "docker ps -a"
EOT
}

output "update_lambda_env_command" {
  value = <<EOT
After CTFd setup, update admin credentials with:
aws lambda update-function-configuration \
  --function-name ${aws_lambda_function.ctfd_sync_challenge.function_name} \
  --environment "Variables={CTFD_URL=http://${aws_instance.ctfd_instance.private_ip}:8000,ADMIN_USERNAME=your_admin,ADMIN_PASSWORD=your_password}"
EOT
}

output "troubleshooting_guide" {
  value = <<EOT
If CTFd is not accessible:
1. Check instance status: aws ec2 describe-instance-status --instance-ids ${aws_instance.ctfd_instance.id}
2. Check security groups: aws ec2 describe-security-groups --group-ids ${aws_security_group.ctfd_sg.id}
3. SSH into instance and check logs: docker logs $(docker ps -aqf "name=ctfd")
4. Verify port 8000 is open: nc -zv ${aws_eip.ctfd_eip.public_ip} 8000
EOT
}