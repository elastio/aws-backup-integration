# Scan AWS backup recovery point for ransomware and malware and send the result to Amazon EventBridge

---

## Prerequisites
- [Terraform CLI]
- [AWS CLI]
- [Elastio CLI]

## Configure EventBridge
The scan reports will be sent to the [EventBridge event bus]. To create it use Terraform and the provided configuration file. It will create the EventBridge bus called `elastio-iscan` in your AWS account.

Perform the following steps:
1. Create `main.tf` file with the content provided below
2. Run `terraform init`
3. Run `terraform apply`

```tf
# This will use the `default` AWS CLI profile
provider "aws" {}

resource "aws_cloudwatch_event_bus" "this" {
  name = "elastio-iscan"
  tags = {
    # ⚠️ This tag is important to grant Elastio write access to the bus
    "elastio:iscan-event-bus" = "true"
  }
}
```

### Deploy the SQS subscriber to EventBridge to view raw events (optional)

This section is optional. Feel free to skip. This will be useful only if you want to review what raw JSON Elasio iscan reports are sent.

For testing purposes, an SQS queue could be created to *manually* view sent events. Use [this terraform configuration](eventbridge-sqs.tf) file to create an EventBridge bus with the SQS queue subscribed to it.

This way Elastio iscan reports will be sent to the SQS queue named `elastio-iscan-receiver`, where you can poll and view them as described in the [further section](#view-the-raw-scan-report-optional).

## Scan an AWS Backup recovery point
Use the command below to import an AWS backup recovery point (RP) to Elastio and run a vulnerability scan.
```bash
elastio aws-backup import --rp-vault [rp-vault] --rp-arn [rp-arn] --iscan --send-event --event-bridge-bus elastio-iscan
```
Where:
- `rp-vault` is the name of the vault where the AWS Backup RP is stored
- `rp-arn` ARN of the AWS Backup RP you would like to scan

![image](https://user-images.githubusercontent.com/81738703/207306745-fa4a8708-a4cb-461c-b5a9-e7ae9495b488.png)

### Scan using AWS Lambda API

It's possible to invoke the same `elastio aws-backup import` operation as described in the section above using our AWS Lambda API. [It's described in detail here](elastio-lambda-api.md).

## View the raw scan report (optional)

This step is optional. Feel free to skip. To see the raw JSON report of the iscan first make sure to do the steps described in [this section](#deploy-the-sqs-subscriber-to-eventbridge-to-view-raw-events-optional). Once that is done, go to SQS and open `elastio-iscan-receiver`. Navigate to `Send and receive messages` and press `Poll for messages`.

![image](https://user-images.githubusercontent.com/81738703/207305818-66544b86-b4fb-4007-ad2a-e0c8e932e1bc.png)

## Recover from a healthy recovery point
Recovery points contain the statuses of scans. There are 2 recovery options:
- Restore an entire recovery point using `elastio restore` command
- Restore individual files from a recovery point using `elastio mount` command

### View recovery point statuses in elastio tenant
To view the recovery point status complete the following actions:
1. In the left navigation menu go to `Assets` page
2. Click on the asset you would like to inspect

Recovery point scan statuses are displayed as red or green icons on each row of the list:

![image](https://user-images.githubusercontent.com/81738703/207309210-1549e916-f358-4b2b-a34d-f122faa1f11d.png)

### Restore from a recovery point
There is an option to restore an EBS volume or an EC2 instance. To do a restore run one of the following commands:
```
elastio ebs restore --rp [rp-ID]
elastio ec2 restore --rp [rp-ID]
```

There is also an option to restore individual files using `elastio mount` command:
```
sudo -E elastio mount rp --rp [rp-ID]
```

These commands can be found in the restore or mount dialog windows in the elastio tenant. To see this command select `Restore` or `Mount` option in the recovery point drop-down menu.

![image](https://user-images.githubusercontent.com/81738703/207312410-aa03fb22-abd4-4975-ba87-0e9b2319727e.png)

[Terraform CLI]: https://developer.hashicorp.com/terraform/downloads?product_intent=terraform
[AWS CLI]: https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html
[Elastio CLI]: https://docs.elastio.com/src/getting-started/install-cli
[EventBridge event bus]: https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-event-bus.html
