module "basic_usage" {
  source            = "JousP/lambda-notification-to-slack/aws"
  version           = "~> 3.2"
  function_name     = "cloudwatch-alarm-to-slack-basic"
  slack_webhook_url = "https://hooks.slack.com/services/XXX/XXX/XXX"
  slack_channel     = "aws-notifications"
}
