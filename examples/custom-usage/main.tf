# Create a custom role for the lambda function
resource "aws_iam_role" "lambda" {
  name               = "lambda-custom-example"
  assume_role_policy = <<-EOF
  {
    "Version": "2012-10-17",
    "Statement": [
      {
        "Action": "sts:AssumeRole",
        "Principal": {
          "Service": "lambda.amazonaws.com"
        },
        "Effect": "Allow",
        "Sid": ""
      }
    ]
  }
EOF
}

resource "aws_iam_role_policy_attachment" "lambda_role" {
  role       = aws_iam_role.lambda.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaVPCAccessExecutionRole"
}

# Create the lambda function
module "custom_usage" {
  source            = "JousP/lambda-notification-to-slack/aws"
  version           = "~> 3.2"
  function_name     = "cloudwatch-alarm-to-slack-custom"
  description       = "Push Cloudwatch Alarms Notifications to Slack"
  slack_webhook_url = "https://hooks.slack.com/services/XXX/XXX/XXX"
  slack_channel     = "aws-notifications"
  slack_username    = "cloudwatch-alarm-to-slack-custom"
  log_events        = true
  create_role       = false
  role              = aws_iam_role.lambda.arn
  vpc_config = {
    subnet_ids         = [aws_subnet.aza.id, aws_subnet.azb.id]
    security_group_ids = [aws_security_group.sg.id]
  }
  permission_principal = "sns.amazonaws.com"
  function_tags = {
    SNSTopic = "MySNSTopic"
  }
}
