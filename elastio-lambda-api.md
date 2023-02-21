## API documentation

Elastio connector exposes an AWS Lambda function with the fixed name `elastio-bg-jobs-service-aws-backup-rp-import`, that starts a background job to import an AWS Backup recovery point into elastio vault, optionally running malware and/or ransomware scanning for it.

## Request
The function accepts JSON input in the following format:

```jsonc
{
    // Name of the source AWS Backup vault.
    // It is assumed that the vault is in the same account and region as the connector.
    //
    // Required.
    "aws_backup_vault": "Default",

    // ARN of the source AWS Backup recovery point
    //
    // Required.
    "aws_backup_rp_arn": "arn:aws:ec2:eu-central-1::snapshot/snap-069324f1f1b639172",

    // Name of the target `elastio` vault.
    //
    // Optional. If omitted or `null` then the default vault is used.
    "elastio_vault": "elastio-vault-name",

    // Options related to running ransomware and malware scanning for the imported recovery point.
    //
    // Optional. If omitted then iscan is disabled by default.
    "iscan": {
        // Optional. If omitted then ransomware scan is disabled by default
        "ransomware": true,

        // Optional. If omitted then malware scan is disabled by default
        "malware": true,

        // Name of the event bus iscan reports will be written to.
        //
        // Optional. If absent or `null`, then the value from `/elastio/iscan-results-eventbridge-bus`
        // SSM parameter will be used. If the SSM parameter isn't set, then the "Default"
        // event bus will be used as the final fallback.
        //
        // To specify the default event bus explicitly, a "Default" string may be passed.
        "event_bridge_bus": "MyBusName"
    }
}
```

## Response

```jsonc
{
    // Describes the AWS Backup rp job that was submitted.
    //
    // Required.
    "job_state": { /* See `job_state` description bellow */ },

    // Describes the subnets that may have misconfiguration (e.g. autoAssignPublicIPv4 is not enabled).
    // When this field is not null or absent, it serves as a hint that the job may not finish successfully.
    //
    // Optional.
    "misconfig": {
        // The list of subnets ARNs that are potentially misconfigured in the VPC where elastio vault was deployed.
        // See elastio documentation on how to properly configure the VPC for vault deployment.
        //
        // Required. At least 1 subnet will be specified if misconfig is present.
        "subnets": ["arn:aws:ec2:eu-central-1:999999999999:subnet/subnet-13ff3fdd4af587824"]
    }
}
```

The `job_state` is a sum type of two shapes. Either one of them can be returned:

```jsonc
{
    // Serves as a discriminator of this shape.
    // Indicates that a new background job was started to import the requested AWS Backup RP.
    //
    // Required.
    "kind": "Created",

    // ID of the started elastio background job.
    //
    // Required.
    "job_id": "j-01ghkcq8g409rxg35x1st6vdzp",

    // Abort token that is used to grant access to aborting the elastio background job.
    //
    // Required.
    "abort_token": "ew64dYAJt5eXlig4j38zY3K++4OPWomo3tdR/lNxE5I="
}
```

OR

```jsonc
{
    // Serves as a discriminator of this shape.
    // Indicates that no new background job was started as a result of this request
    //
    // Required.
    "kind": "Existing",

    // ID of the existing elastio background job that was already in the process of importing
    // the requested AWS Backup RP.
    //
    // Required.
    "job_id": "j-01ghkcq8g409rxg35x1st6vdzp",
}
```

## Examples

### Success

<details>
<summary>Submitting a new import new job</summary>

```
$ aws lambda invoke --function-name elastio-bg-jobs-service-aws-backup-rp-import --cli-binary-format raw-in-base64-out --payload '{ "aws_backup_vault": "Default", "aws_backup_rp_arn": "arn:aws:ec2:eu-central-1::snapshot/snap-069324f1f1b639172" }' out.log.json
{
    "StatusCode": 200,
    "ExecutedVersion": "$LATEST"
}
$ cat out.log.json | jq
```
```json
{
  "job_state": {
    "kind": "Created",
    "job_id": "j-01ghkcq8g409rxg35x1st6vdzp",
    "abort_token": "ew64dYAJt5eXlig4j38zY3K++4OPWomo3tdR/lNxE5I="
  },
  "misconfig": null
}
```

</details>

<details>
<summary>Submitting an import job when one already runs for the RP</summary>

```
$ aws lambda invoke --function-name elastio-bg-jobs-service-aws-backup-rp-import --cli-binary-format raw-in-base64-out --payload '{ "aws_backup_vault": "Default", "aws_backup_rp_arn": "arn:aws:ec2:eu-central-1::snapshot/snap-069324f1f1b639172" }' dbg.json; jq '' dbg.json
{
    "StatusCode": 200,
    "ExecutedVersion": "$LATEST"
}
```
```json
{
  "job_state": {
    "kind": "Existing",
    "job_id": "j-01ghkd2x2q8kg40che9zxr0kxv"
  },
  "misconfig": null
}
```

</details>

### Failure

<details>
<summary>Error finding a recovery point in existing vault</summary>

```
$ aws lambda invoke --function-name elastio-bg-jobs-service-aws-backup-rp-import --cli-binary-format raw-in-base64-out --payload '{ "aws_backup_vault": "Default", "aws_backup_rp_arn": "arn:aws:backup:eu-central-1:528005273388:recoveryPoint:RecoveryPointId" }' dbg.json; open dbg.json
{
    "StatusCode": 200,
    "FunctionError": "Unhandled",
    "ExecutedVersion": "$LATEST"
}
╭──────────────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ errorType    │ &aws_lambda_runtime::error::Error                                                                                                               │
│ errorMessage │ Failed to describe recovery point `arn:aws:backup:eu-central-1:528005273388:recoveryPoint:RecoveryPointId` in AWS Backup vault `Default`        │
│              │                                                                                                                                                 │
│              │ Caused by:                                                                                                                                      │
│              │     0: Failed to describe recovery point `arn:aws:backup:eu-central-1:528005273388:recoveryPoint:RecoveryPointId` in AWS Backup vault `Default` │
│              │     1: ResourceNotFoundException: Cannot find recovery point                                                                                    │
│              │     2: ResourceNotFoundException: Cannot find recovery point                                                                                    │
╰──────────────┴─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```
</details>

<details>
<summary>Non-existent AWS backup vault was specified</summary>

```
$ aws lambda invoke --function-name elastio-bg-jobs-service-aws-backup-rp-import --cli-binary-format raw-in-base64-out --payload '{ "aws_backup_vault": "non_existent", "aws_backup_rp_arn": "arn:aws:backup:eu-central-1:528005273388:recoveryPoint:RecoveryPointId" }' dbg.json; open dbg.json
{
    "StatusCode": 200,
    "FunctionError": "Unhandled",
    "ExecutedVersion": "$LATEST"
}
╭──────────────┬────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ errorType    │ &aws_lambda_runtime::error::Error                                                                                                                              │
│ errorMessage │ Failed to describe recovery point `arn:aws:backup:eu-central-1:528005273388:recoveryPoint:RecoveryPointId` in AWS Backup vault `non_existent`                  │
│              │                                                                                                                                                                │
│              │ Caused by:                                                                                                                                                     │
│              │     0: Failed to describe recovery point `arn:aws:backup:eu-central-1:528005273388:recoveryPoint:RecoveryPointId` in AWS Backup vault `non_existent`           │
│              │     1: Error { code: "AccessDeniedException", message: "Insufficient privileges to perform this action.", request_id: "86150926-5cef-4124-9c92-12b8f3abe5d2" } │
│              │     2: Error { code: "AccessDeniedException", message: "Insufficient privileges to perform this action.", request_id: "86150926-5cef-4124-9c92-12b8f3abe5d2" } │
╰──────────────┴────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

</details>

<details>
<summary>Missing default elastio vault</summary>

```
$ aws lambda invoke --function-name elastio-bg-jobs-service-aws-backup-rp-import --cli-binary-format raw-in-base64-out --payload '{ "aws_backup_vault": "Default", "aws_backup_rp_arn": "arn:aws:ec2:eu-central-1::snapshot/snap-069324f1f1b639172" }' out.log.json; open out.log.json
{
    "StatusCode": 200,
    "FunctionError": "Unhandled",
    "ExecutedVersion": "$LATEST"
}
╭──────────────┬─────────────────────────────────────────────────────────────────────────────────────────────────────────╮
│ errorType    │ &aws_lambda_runtime::error::Error                                                                       │
│ errorMessage │ Failed to select elastio vault. No vault was specified in the request and the default one doesn't exist │
╰──────────────┴─────────────────────────────────────────────────────────────────────────────────────────────────────────╯
```

</details>

<details>
<summary>Non-existent elastio vault</summary>

```
$ aws lambda invoke --function-name elastio-bg-jobs-service-aws-backup-rp-import --cli-binary-format raw-in-base64-out --payload '{ "aws_backup_vault": "Default", "aws_backup_rp_arn": "arn:aws:ec2:eu-central-1::snapshot/snap-069324f1f1b639172", "elastio_vault": "invalid-elastio-vault" }' out.log.json; open out.log.json
{
    "StatusCode": 200,
    "FunctionError": "Unhandled",
    "ExecutedVersion": "$LATEST"
}
╭──────────────┬───────────────────────────────────────────────────────╮
│ errorType    │ &aws_lambda_runtime::error::Error                     │
│ errorMessage │ Specified vault "invalid-elastio-vault" doesn't exist │
╰──────────────┴───────────────────────────────────────────────────────╯
```

</details>

### Demo

Here is a short demo recording of using and testing the API. Don't forget to press the unmute button in the video player below.

https://user-images.githubusercontent.com/36276403/211019809-ac50528b-711c-45a2-b135-2b7aa1592851.mp4
