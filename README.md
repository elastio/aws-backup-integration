# AWS Backup Elastio Integration to Help Protect Data from Ransomware, Malware, and Corruption.

Authored by: Adam Nelson, CTO of Elastio, Cris Daniluk, AWS Security Architect, RhythmicTech.

Typically, the first time backups are tested at the point of recovery. Those backups often contain latent corruption, malware, and files that cannot be restored due to ransomware. Elastio now integrates with AWS Backup to continuously scan backups for these threats, recovery testing them to ensure a successful restoration, and quickly identifying the last clean recovery point. 

Using Elastio, AWS Backup customers have confidence that their data is recoverable in case of ransomware, corruption, or any other threat. Due to its compression and deduplication capabilities, customers can increase their retention period while simultaneously reducing their storage costs. The entire process is run from within the customer’s AWS Organization. Elastio cannot view, access, or gain custody of customer data. By implementing Elastio, customers can better meet compliance requirements and decrease their overall risk and spend. 

Elastio ingests AWS Backup recovery points into its ScaleZ storage engine, scanning backups in real-time for ransomware, malware, corruption, and other factors that affect restorability. Once configured, the integration is seamless, using Amazon EventBridge to receive notifications as new recovery points are created with the customer’s existing AWS Backup Vaults. Scan results can be consumed and alerted in real-time by security tools such as AWS Audit Manager, AWS Security Hub, Splunk, and Datadog. 

![Picture1](https://user-images.githubusercontent.com/81738703/219877966-e0eea261-0946-412a-80c3-d03511c55fa7.png)

If a cyber threat is detected and needs to be remediated, Elastio provides the ability to provide historical context and reconstitute material information for forensic interrogation from its cyber vault. 

In one click, customers can easily recover entire instances, selected volumes, or individual files to a secure and isolated environment. Elastio is also designed to integrate with existing incident response procedures. It supports sending logs, events, and alerts to leading SIEMs.

## AWS Backup and Elastio Architectures

### Single Account Configuration

![Picture2](https://user-images.githubusercontent.com/81738703/219877974-18b98685-e50a-49f3-971f-a80060b24ba5.png)

1. AWS Backup creates a recovery point for an Amazon EC2 instance in the Workload Account.
2. An Amazon EventBridge event is triggered when the backup for the Amazon EC2 instance is completed.
3. The event triggers an AWS Lambda function that invokes an Elastio processing pipeline. The pipeline imports the recovery point and performs a cyber scan on all associated objects, including the Amazon EBS volumes and the Amazon Machine Image.
4. After the pipeline completes, detailed artifacts are generated and sent to Amazon EventBridge. 
5. A Job Status Lambda function is triggered to copy the artifacts to an Amazon S3 bucket. 
6. The artifacts are stored in an Amazon S3 bucket. Alternatively, the AWS Lambda can be modified to send artifacts to any system, including AWS Security Hub, Datadog, and Splunk.

### Cross Account Configuration

![Picture3](https://user-images.githubusercontent.com/81738703/219877989-478ccc6f-1780-4064-a39c-48a0b3965b61.png)

1. AWS Backup creates a recovery point for an Amazon EC2 instance.
2. The Default Event Bridge event is triggered when the backup for the Amazon EC2 instance is completed, and the copy is initiated.
3. When the copy is completed, the Job Status Event Bridge triggers an AWS Lambda function that invokes an Elastio processing pipeline. 
4. The pipeline imports the recovery point and performs a cyber scan on all associated objects, including the Amazon EBS volumes and the Amazon Machine Image.
5. After the pipeline completes, detailed artifacts are generated and sent to Amazon EventBridge. 
6. A Job Status Lambda function is triggered to copy the artifacts to an Amazon S3 bucket. The artifacts are stored in an Amazon S3 bucket. Alternatively, the AWS Lambda can be modified to send artifacts to any system, including AWS Security Hub, Datadog, and Splunk.


### Deploying AWS Backup CloudFormation

1. Log in to the AWS Account where the AWS Backup Vault exists.
2. From CloudFormation console, select Create Stack, Select "With New Resources".
3. Select "Upload Template File" and upload the YAML file.
4. Enter the stack name "aws-backup-elastio-integration"
5. Enter an S3 bucket name.  
6. Enter the ARN of Lamdba "elastio-bg-jobs-service-aws-backup-rp-import"
7. Optionally use all defaults and follow the wizard to create the stack.

NOTE: By using the Lambda provided in the AWS Backup Elastic integration, all backups will undergo scanning for all policies. In a future blog, instructions will be given on creating custom backup rules, which will involve modifying the Lambda that handles new AWS Backup events to exclude certain backups based on specific criteria.

  **Elastio_stack.yaml**
```
AWSTemplateFormatVersion: 2010-09-09
Description: Component that integrates AWS Backup with Elastio 
Metadata:
  AWS::CloudFormation::Interface:
    ParameterGroups:
      - Label:
          default: Reporter Configuration
        Parameters: 
            - LogsBucketName  
            - ElastioImportLambdaARN            
    ParameterLabels:
      LogsBucketName:
        default: S3 Bucket for Elastio Logs and Data 
      ElastioImportLambdaARN:
        default: The ARN of Elastio Lambda for importing a RecoveryPoint
Parameters:
  LogsBucketName:
    Description: The S3 Bucket Name where the Job Logs and Reports are to be stored. 
    Type: String
  ElastioImportLambdaARN:
    Description: The ARN of Elastio Lambda for importing a RecoveryPoint
    Type: String     
Resources: 

  ProcessAWSBackupVaultStatusEventRuleForElastio: 
    Type: AWS::Events::Rule
    Properties: 
      Name: ProcessAWSBackupVaultStatusEventRuleForElastio
      Description: "Rule to direct AWS Backup Events to Status Handler Lambda"
      State: "ENABLED"
      EventPattern: 
        source:
          - 'aws.backup'
        detail-type:
          - 'Backup Job State Change'
      Targets: 
        - Arn: !GetAtt
                  - ElastioStatusHandlerLambda
                  - Arn
          Id: "ProcessAWSBackupEventsUsingLambda" 
          
  ProcessAWSBackupVaultStatusEventRuleForElastioInvokePermission:
    Type: 'AWS::Lambda::Permission'
    Properties:
      Action: 'lambda:InvokeFunction'
      FunctionName: !Ref ElastioStatusHandlerLambda
      Principal: events.amazonaws.com
      SourceArn: !Sub ${ProcessAWSBackupVaultStatusEventRuleForElastio.Arn}
      
  ElastioStatusHandlerLambda:
    Type: AWS::Lambda::Function
    Metadata:
        cfn_nag:
          rules_to_suppress:
            - id: W89
              reason: "NA"
            - id: W92
              reason: "NA"    
    Properties:
      Code:
        ZipFile: |-
          #!/usr/bin/env python
          # -*- coding: utf-8 -*-
          import json
          import boto3
          import urllib3
          import traceback
          import os
          import shutil
          from urllib.parse import urlparse
          from botocore.exceptions import ClientError
          def lambda_handler(event, context):
            try:
                print(f'Handling event : {event}')
                if event.get('source') == 'elastio.iscan':
                    job_event_type = 'scan_results'
                    event['job_type']=job_event_type
                    event['job_id']=event.get('id')
                    save_event_data_to_s3(event['id'], event)
                
                #Process AWS Backup Job completion event to trigger Elastio Scan
                elif event.get('source') == 'aws.backup':
                    event_detail = event.get('detail')                
                    job_event_state = event_detail.get('state')
                    if not job_event_state:
                        # Hack
                        job_event_state = event_detail.get('status')
                    if job_event_state in ('COMPLETED'):
                        try:
                            backupvault_name = event_detail.get('backupVaultName')
                            job_id = event_detail.get('backupJobId')
                            backup_client = boto3.client('backup')
                            try:
                                # boto3 API  /services/backup.html#Backup.Client.describe_backup_job
                                backup_info = backup_client.describe_backup_job(BackupJobId=job_id)
                                if 'ResponseMetadata' in backup_info:
                                    del backup_info['ResponseMetadata']
                    
                                print(f"backup_info : {backup_info}")      
                            except botocore.exceptions.ClientError as e:
                                    if e.response['Error']['Code'] == "ResourceNotFoundException":
                                        print(f"Backup Job with ID : {job_id} not found")
                                    else:
                                        print(f"Error : {e} processing describe_backup_job")
                    
                            recovery_point_arn = backup_info['RecoveryPointArn']  
                            
                            elastio_status_eb = os.environ.get('ElastioStatusEB') 
                            if not elastio_status_eb:
                                elastio_status_eb = 'elastio-scan-results'
                              
                            elastio_lambda_arn = os.environ.get('ElastioImportLambdaARN') 
                            if not elastio_lambda_arn:
                                raise Exception('ElastioImportLambdaARN is missing!') 
                              
                            #invoke the lambda
                            input_params = {
                                              "aws_backup_vault": backupvault_name,
                                              "aws_backup_rp_arn": recovery_point_arn,
                                              "iscan": {
                                                "ransomware": True,
                                                "malware": True,
                                                "event_bridge_bus": elastio_status_eb
                                              }
                                            }
                            print(f'invoking {elastio_lambda_arn} with {input_params}')
                            try:
                                boto3.client('lambda').invoke(
                                    FunctionName=elastio_lambda_arn,
                                    InvocationType='Event',
                                    Payload=json.dumps(input_params)
                                )
    
                            except (ClientError, Exception):  # pylint: disable = W0703
                                var = traceback.format_exc()
                                print(f"Error {var} processing invoke")                         
                            
                        except Exception:
                            var = traceback.format_exc()
                            print(f"Error {var} in lambda_handler while handling elastio.iscan")
            except Exception as e:
                print(f'{e}')
                
          def save_event_data_to_s3(job_id, json_content):
              """
              This method is responsible for writing the job info (jsonContent) to the
              folder (destFolder) under the key (jobId)
              """
              s3_log_bucket = os.environ.get('LogsBucketName') 
              if not s3_log_bucket:
                  raise Exception('LogsBucketName is missing!') 
              s3_log_location = 'elastio-scan-results/' + job_id + '.json'

              try:
                  print(f"Persisting event data to : {s3_log_bucket} at {s3_log_location}")
                  s3_client = boto3.client('s3')
                  print(f"Logging to : {s3_log_bucket} at {s3_log_location}")
                  s3_client.put_object(Body=json.dumps(json_content,
                                                       default=str, separators=(',', ':')),
                                       Bucket=s3_log_bucket,
                                       Key=s3_log_location, ACL='bucket-owner-full-control',
                                       Tagging='Source=ElastioResults')
                                            
              except (ClientError, Exception):
                  var = traceback.format_exc()
                  print(f"Error {var} processing save_event_data_to_s3")                

      Description: Handle AWS Backup and Elastio Scan results
      Handler: index.lambda_handler
      Role : !GetAtt ElastioStatusHandlerLambdaRole.Arn
      Runtime: python3.7
      Timeout: 900
      Environment:
        Variables:
          ElastioStatusEB : !Ref ElastioJobStatusEventBus 
          LogsBucketName: !Ref LogsBucketName
          ElastioImportLambdaARN : !Ref ElastioImportLambdaARN

  ElastioJobStatusEventBus:
    Type: AWS::Events::EventBus
    Properties:
      Name: !Join [ '', ['ElastioJobStatusEventBus-', !Ref 'AWS::AccountId'] ]

  ElastioStatusEventBridgeInvokePermission:
    Type: 'AWS::Lambda::Permission'
    Properties:
      Action: 'lambda:InvokeFunction'
      FunctionName: !Ref ElastioStatusHandlerLambda
      Principal: events.amazonaws.com
      SourceArn: !Sub ${ElastioStatusEventRule.Arn}    
  
  ElastioStatusEventRule: 
    Type: AWS::Events::Rule
    Properties: 
      Description: "Send Elastio events to Lambda"
      EventBusName: !Ref ElastioJobStatusEventBus
      State: "ENABLED"
      EventPattern: 
        source:
          - 'elastio.iscan'
      Targets: 
        - Arn: !GetAtt ElastioStatusHandlerLambda.Arn
          Id: "ElastioStatusEvent"
  
  ElastioJobStatusEventBusPolicy:
    Type: AWS::Events::EventBusPolicy
    Properties: 
        EventBusName: !Ref ElastioJobStatusEventBus
        StatementId: "ElastioStatusEventBridgePolicyStmt"
        Statement: 
            Effect: "Allow"
            Principal: "*"
            Action: "events:PutEvents"
            Resource: !GetAtt "ElastioJobStatusEventBus.Arn"

  ElastioStatusHandlerLambdaRole:
    Type: 'AWS::IAM::Role'
    Metadata:    
      cfn_nag:
        rules_to_suppress:
          - id: F3
          - id: W11
    Properties:
      AssumeRolePolicyDocument:
        Version: 2012-10-17
        Statement:
          - Effect: Allow
            Principal:
              Service: lambda.amazonaws.com
            Action: 'sts:AssumeRole'
          - Effect: Allow
            Principal:
              Service: 'quicksight.amazonaws.com'
            Action:
            - 'sts:AssumeRole'              
      ManagedPolicyArns:
          - !Sub 'arn:${AWS::Partition}:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole'
      Policies:
          - PolicyName: invokeLambda
            PolicyDocument:
              Version: '2012-10-17'
              Statement:
              - Effect: Allow
                Action:
                - lambda:InvokeFunction
                Resource: '*'           
          - PolicyName: s3Permissions
            PolicyDocument:
              Statement:
              - Effect: Allow
                Action:
                  - kms:GenerateDataKey
                  - kms:Decrypt
                  - kms:Encrypt                  
                  - s3:PutObject*
                  - s3:GetObject*
                  - s3:DeleteObject
                  - s3:*BucketNotification
                  - s3:GetBucketLocation
                  - s3:ListBucket
                  - s3:ListBucketMultipartUploads
                  - s3:ListMultipartUploadParts
                  - s3:AbortMultipartUpload                  
                Resource:
                  - !Sub 'arn:${AWS::Partition}:s3:::${LogsBucketName}/*'
                  - !Sub 'arn:${AWS::Partition}:s3:::${LogsBucketName}'
          - PolicyName: backupPermissions
            PolicyDocument:
              Version: '2012-10-17'
              Statement:
              - Effect: Allow
                Action:
                - backup:DescribeBackupJob
                Resource: '*'                      
          - PolicyName: logStreamPermissions
            PolicyDocument:
              Statement:                       
              - Effect: Allow
                Action:
                  - 'logs:CreateLogGroup'
                  - 'logs:CreateLogStream'
                  - 'logs:PutLogEvents'
                Resource: !Sub 'arn:${AWS::Partition}:logs:*:*:*'                        
          - PolicyName: GlueAthenaPermissions
            PolicyDocument:
              Statement:
              - Effect: Allow
                Action:
                  - athena:*
                  - glue:*
                Resource: '*'

  ElastioStatusLogsDB:
    Type: AWS::Glue::Database
    Properties:
      CatalogId: !Ref "AWS::AccountId"
      DatabaseInput:
        Description: ElastioStatusLogsDB
        Name: elastio-logs-db
  AthenaWorkgroup:
    Type: AWS::Athena::WorkGroup
    Properties: 
      Name: !Sub "${AWS::StackName}-elastio-handler-for-aws-backup-wg"
      RecursiveDeleteOption: true
      State: ENABLED
      WorkGroupConfiguration: 
        ResultConfiguration: 
          OutputLocation: !Sub 's3://${LogsBucketName}/elastio-logs/athena_results/'
            
Outputs:
  StackName:
    Value: !Ref AWS::StackName
```

### Deploying Elastio

Elastio is deployed in the account that contains the AWS Backup Vault in which you want the recovery points scanned for cyber threats.

1. From [elastio.com](http://www.elastio.com) select “login” and “create new account”.  Follow the process to create a new tenant.
2. From the tenant, select On-Boarding and select Deploy.
3. Deploy the CFN in the same account that contains the AWS Backup Vault.
4. Deploy the Cloud Connector in the same region and the AWS Backup Vault.
5. Proceed to deploy the Job Trigger and Job Status Lambda’s as described above.
6. If you have existing AWS Backup policies, they will work without changes. If not, create a policy to protect your EC2 instances.

### Run Your First Backup and Scan

1. From the AWS Backup console, go to Dashboard and select "Create on-demand backup".
2. Select EC2 or EBS to backup and press "Create on-demand backup" button.
3. The scan results artifacts will be available in the S3 bucket provided in the CloudFormation definition. The results are presented in JSON.

From the Elastio Tenant.
1. Select Jobs
2. View the import and iscan jobs to validate the process.
3. Once complete, from the job list, select the recovery point id and view the results.  

The results from the Elastio Tenant:
![image](https://user-images.githubusercontent.com/81738703/220642633-9c2d373a-3c0f-4e39-9248-e18db6f2b8a3.png)

The results in the S3 bucket:

![image](https://user-images.githubusercontent.com/81738703/219956284-582a780c-463b-4b69-81b7-8500b44a7962.png)

### Conclusion
By using Elastio to enhance AWS Backup, organizations can secure their cloud data, reduce data loss and downtime, and improve Recovery Time Objectives (RTO) in case of an attack or application failure. Elastio imports AWS Backups as globally deduplicated and compressed, resulting in improved scan performance, shorter recovery times, and cost savings.

AWS customers can contact [sales@elastio.com](mailto:sales@elastio.com) to set up a demo of Elastio or they can download the product from [AWS Marketplace](https://aws.amazon.com/marketplace/pp/prodview-jvce2rake3i3i?sr=0-1&ref_=beagle&applicationId=AWSMPContessa). A free tier that covers 1TB of protected data with a seven-day retention period and a free 30-day trial with full functionality and unlimited retention are both available. See [Elastio’s pricing page](https://elastio.com/pricing/) for full details. 
