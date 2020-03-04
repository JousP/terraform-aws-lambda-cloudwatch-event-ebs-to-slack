locals {
  default            = {
    role_name        = var.role_name == "" ? "role_${var.function_name}" : var.role_name
    role_description = var.role_description == "" ? "Role for lambda function ${var.function_name}" : var.role_description
  }
  role               = var.role == null ? module.role.arn : var.role
}

module "role" {
  source                = "JousP/iam-assumeRole/aws"
  version               = "~> 2.1.0"
  enabled               = var.create_role
  name                  = local.default["role_name"]
  description           = local.default["role_description"]
  assume_role_policy    = var.role_assume_role_policy
  force_detach_policies = var.role_force_detach_policies
  path                  = var.role_path
  max_session_duration  = var.role_max_session_duration
  permissions_boundary  = var.role_permissions_boundary
  tags                  = merge(var.tags, var.role_tags)
  policies_count        = var.role_policies_count
  policies              = var.role_policies
  json_policies_count   = var.role_json_policies_count
  json_policies         = var.role_json_policies
  service_identifiers   = ["lambda.amazonaws.com"]
}

data "null_data_source" "function_file" {
  inputs = {
    filename = "${path.module}/lambda/function.py"
  }
}

data "null_data_source" "function_archive" {
  inputs = {
    filename = "${path.module}/lambda/function.zip"
  }
}

data "archive_file" "function_filename" {
  type        = "zip"
  source_file = data.null_data_source.function_file.outputs.filename
  output_path = data.null_data_source.function_archive.outputs.filename
}

# Create the Lambda Function
resource "aws_lambda_function" "main" {
  count                          = var.enabled ? 1 : 0
  filename                       = data.archive_file.function_filename.output_path
  function_name                  = var.function_name
  handler                        = "function.lambda_handler"
  role                           = local.role
  description                    = var.description
  memory_size                    = var.memory_size
  runtime                        = "python3.7"
  timeout                        = var.timeout
  reserved_concurrent_executions = var.reserved_concurrent_executions
  publish                        = var.publish
  kms_key_arn                    = var.kms_key_arn
  source_code_hash               = data.archive_file.function_filename.output_base64sha256
  tags                           = merge(var.tags, var.function_tags)
  environment {
    variables           = {
      SLACK_WEBHOOK_URL = var.slack_webhook_url
      SLACK_CHANNEL     = var.slack_channel
      SLACK_USERNAME    = var.slack_username
      SLACK_EMOJI       = var.slack_emoji
      LOG_EVENTS        = var.log_events ? "True" : "False"
    }
  }
  dynamic "dead_letter_config" {
    for_each     = var.dead_letter_config == null ? [] : [var.dead_letter_config]
    content {
      target_arn = lookup(dead_letter_config.value, "target_arn", null)
    }
  }
  dynamic "vpc_config" {
    for_each             = var.vpc_config == null ? [] : [var.vpc_config]
    content {
      subnet_ids         = vpc_config.value.subnet_ids
      security_group_ids = vpc_config.value.security_group_ids
    }
  }
  dynamic "tracing_config" {
    for_each = var.tracing_config == null ? [] : [var.tracing_config]
    content {
      mode   = tracing_config.value.mode
    }
  }
  lifecycle {
    ignore_changes               = [last_modified]
  }
}

# Creates a Lambda function alias.
resource "aws_lambda_alias" "main" {
  count            = var.enabled && var.create_alias ? 1 : 0
  name             = var.alias_name
  description      = "${var.function_name} ${var.alias_name} version"
  function_name    = aws_lambda_function.main[0].arn
  function_version = var.alias_function_version
}

# Allow `permission_principal` to Trigger Lambda Execution
locals {
  id            = "${var.function_name}_${element(split(".", var.permission_principal), 0)}"
  permission_sid = var.permission_statement_id != null ? var.permission_statement_id : var.permission_statement_id_prefix != null ? var.permission_statement_id : local.id
  alias_id  = "${var.function_name}_${element(split(".", var.alias_permission_principal), 0)}"
  alias_permission_sid = var.alias_permission_statement_id != null ? var.alias_permission_statement_id : var.alias_permission_statement_id_prefix != null ? var.alias_permission_statement_id : local.alias_id
}

resource "aws_lambda_permission" "main" {
  count               = var.enabled && var.permission_principal != "" ? 1 : 0
  function_name       = aws_lambda_function.main[0].arn
  action              = var.permission_action
  event_source_token  = var.permission_event_source_token
  principal           = var.permission_principal
  source_arn          = var.permission_source_arn
  statement_id        = local.permission_sid
  statement_id_prefix = var.permission_statement_id_prefix
}

resource "aws_lambda_permission" "alias" {
  count               = var.enabled && var.create_alias && var.alias_permission_principal != "" ? 1 : 0
  function_name       = aws_lambda_function.main[0].id
  action              = var.alias_permission_action
  event_source_token  = var.permission_event_source_token
  principal           = var.alias_permission_principal
  qualifier           = var.alias_name
  source_arn          = var.alias_permission_source_arn
  statement_id        = local.alias_permission_sid
  statement_id_prefix = var.alias_permission_statement_id_prefix
  depends_on          = [aws_lambda_alias.main]
}

# Lambda functions automaticly logs... place some retention policy
resource "aws_cloudwatch_log_group" "lambda" {
  count             = var.enabled ? 1 : 0
  name              = "/aws/lambda/${var.function_name}"
  retention_in_days = var.log_group_retention_in_days
  tags              = merge(var.tags, var.function_tags)
}
