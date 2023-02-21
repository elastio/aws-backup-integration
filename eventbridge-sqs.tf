# This will use the `default` AWS CLI profile
provider "aws" {}

resource "aws_cloudwatch_event_bus" "this" {
  name = "elastio-iscan"
  tags = {
    # ⚠️ This tag is important to grant Elastio write access to the bus
    "elastio:iscan-event-bus" = "true"
  }
}

# Define the SQS queue that will receive the events from the EventBridge bus
resource "aws_sqs_queue" "this" {
  name = "elastio-iscan-receiver"
}

# Allow EventBridge to write to the SQS queue
resource "aws_sqs_queue_policy" "allow_event_bridge_write_to_sqs" {
  policy    = data.aws_iam_policy_document.allow_event_bridge_write_to_sqs.json
  queue_url = aws_sqs_queue.this.id
}

data "aws_iam_policy_document" "allow_event_bridge_write_to_sqs" {
  statement {
    effect = "Allow"
    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }
    actions   = ["sqs:SendMessage"]
    resources = [aws_sqs_queue.this.arn]
  }
}

# Configure EventBridge to send events to the SQS queue
resource "aws_cloudwatch_event_target" "sqs" {
  rule           = aws_cloudwatch_event_rule.this.name
  arn            = aws_sqs_queue.this.arn
  event_bus_name = aws_cloudwatch_event_bus.this.name
}

resource "aws_cloudwatch_event_rule" "this" {
  name           = "elastio-iscan"
  event_pattern  = jsonencode({ source = ["elastio.iscan"] })
  event_bus_name = aws_cloudwatch_event_bus.this.name
}
