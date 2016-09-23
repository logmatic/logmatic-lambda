# logmatic-lambda
*Link to the Logmatic.io documentation: http://doc.logmatic.io/docs/aws-lambda-s3*

AWS lambda function to ship ELB, S3, CloudTrail, VPC, CloudFront and CloudWatch logs to Logmatic.io

# Features

- Use AWS Lambda to re-route triggered S3 events to Logmatic.io
- ELB, S3, CloudTrail, VPC and CloudFont logs can be forwarded
- SSL Security
- JSON events providing details about S3 documents forwarded
- Structured meta-information can be attached to the events

# Quick Start

The provided Python script must be deployed into your AWS Lambda service. We will explain how in this step-by-step tutorial.

## 1. Create a new Lambda function

Select the `s3-get-object-python` blue print. It has been designed to listen S3 created document and trigger actions.

Let's configure it now.

## 2. Configure the Lambda function

- Select S3 event source and:
  - The bucket where your logs are located and prefix if it applies
  - The event type: `Object Created (All)`

## 3. Provide the code

- Give the function name you want
- Set the Python 2.7 runtime and:
  -  Copy-paste the [content](https://github.com/logmatic/logmatic-lambda/blob/master/lambda_function.py) of the `lambda_function.py` file in the Python editor of the AWS Lambda interface.

### Parameters

At the top of the script you'll find a section called `#Parameters`, that's where you want to edit your code.

```
#Parameters
logmaticKey = "<your_api_key>"
metadata = {"aws":{"type": "s3_logs"}}
```

- **API key**:

Replace `<your_api_key>`: The Logmatic.io's API key is available your platform.

- **metadata**:

You can optionally change the structured metadata. The metadata is merged to all the log events sent by the Lambda script.

## 4. Handler role

To allow access to the S3 objects you must define a S3 execution role and assign it to the Lambda function.

The role must be created into the IAM Management Console as follow:
- Select `Roles`
- Create new Roles
- Follow instructions and select `AWS Lambda` then the `AWSLambdaExecute` policy

Then attach it to your Lambda function.

## 5. Set memory and timeout

Set the memory to the highest possible value.
Set also the timeout limit. Logmatic.io recommends the highest possible value to deal with big files.



## 6. Testing it

You are all set!

The test should be quite natural if the pointed bucket(s) are filling up. There may be some latency between the time a S3 log file is posted and the Lambda function wakes up.

# Suggestions

If you have any suggestions you are more than welcome to comment or propose pull requests on this project!
