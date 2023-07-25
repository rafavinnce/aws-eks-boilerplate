resource "aws_iam_role" "ec2_role" {
  name                = "${var.name}-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Sid    = ""
        Principal = {
          Service = "ec2.amazonaws.com"
          AWS = "arn:aws:iam::334901168872:role/C2G-N3"
        }
      },
    ]
  })
}

resource "aws_iam_policy" "ec2_policy" {
  name = "${var.name}-ec2_policy"
  path = "/"
  description = "Policy to provide permissions on EC2"
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = [
          "*",
        ]
        Effect   = "Allow"
        Resource = "*"
      },
    ]
  })
}

resource "aws_iam_policy_attachment" "ec2_policy_role" {
  name       = "${var.name}-ec2_attachment"
  roles = [aws_iam_role.ec2_role.name]
  policy_arn = aws_iam_policy.ec2_policy.arn
}

resource "aws_iam_instance_profile" "ec2_profile" {
  name       = "${var.name}-ec2_profile"
  role       = aws_iam_role.ec2_role.name
}

