from __future__ import print_function

import base64
import json
import urllib
import boto3
import socket
import ssl
import re
import StringIO
import gzip

# Parameters
logmaticKey = "<your_api_key>"
metadata = {
    "your_metafields": {
        "backend": "python"
    },
    "some_field": "change_me"
}

# Constants
host = "api.logmatic.io"
raw_port = 10514

# SSL security
# while creating the lambda function
enable_security = True
ssl_port = 10515


def lambda_handler(event, context):
    # Check prerequisites
    if logmaticKey == "<your_api_key>" or logmaticKey == "":
        raise Exception(
                "You must configure your API key before starting this lambda function (see #Parameters section)")

    # Attach Logmatic.io's Socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    port = raw_port
    if enable_security:
        s = ssl.wrap_socket(s)
        port = ssl_port

    s.connect((host, port))

    # Add the context to meta
    metadata["aws"] = {}
    metadata["aws"]["function_name"] = context.function_name
    metadata["aws"]["function_version"] = context.function_version
    metadata["aws"]["invoked_function_arn"] = context.invoked_function_arn
    metadata["aws"]["memory_limit_in_mb"] = context.memory_limit_in_mb

    try:

        # Route to the corresponding parser
        event_type = parse_event_type(event)

        if event_type == "s3":
            logs = s3_handler(s, event)

        elif event_type == "awslogs":
            logs = awslogs_handler(s, event)

        for log in logs:
            send_entry(s, log)

    except Exception as e:
        # Logs through the socket the error
        err_message = 'Error parsing the object. Exception: {}'.format(str(e))
        send_entry(s, err_message)
        raise e
    finally:
        s.close()


# Utility functions

def parse_event_type(event):
    if "Records" in event and len(event["Records"]) > 0:
        if "s3" in event["Records"][0]:
            return "s3"

    elif "awslogs" in event:
        return "awslogs"

    raise Exception("Event type not supported (see #Event supported section)")


# Handle S3 events
def s3_handler(s, event):
    s3 = boto3.client('s3')

    # Get the object from the event and show its content type
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = urllib.unquote_plus(event['Records'][0]['s3']['object']['key']).decode('utf8')

    # Extract the S3 object
    response = s3.get_object(Bucket=bucket, Key=key)
    body = response['Body']
    data = body.read()

    structured_logs = []

    # If the name has a .gz extension, then decompress the data
    if key[-3:] == '.gz':
        with gzip.GzipFile(fileobj=StringIO.StringIO(data)) as decompress_stream:
            data = decompress_stream.read()

    if is_cloudtrail(str(key)) is True:
        cloud_trail = json.loads(data)
        for event in cloud_trail['Records']:
            # Create structured object
            structured_line = merge_dicts(event, {"aws": {"s3": {"bucket": bucket, "key": key}}})
            structured_logs.append(structured_line)
    else:
        # Send lines to Logmatic.io
        for line in data.splitlines():
            # Create structured object
            structured_line = {"aws": {"s3": {"bucket": bucket, "key": key}}, "message": line}
            structured_logs.append(structured_line)

    return structured_logs


# Handle CloudWatch events and logs
def awslogs_handler(s, event):
    # Get logs
    with gzip.GzipFile(fileobj=StringIO.StringIO(base64.b64decode(event["awslogs"]["data"]))) as decompress_stream:
        data = decompress_stream.read()
    logs = json.loads(str(data))

    structured_logs = []

    # Send lines to Logmatic.io
    for log in logs["logEvents"]:
        # Create structured object and send it
        structured_line = merge_dicts(log, {
            "aws": {
                "awslogs": {
                    "logGroup": logs["logGroup"],
                    "logStream": logs["logStream"],
                    "owner": logs["owner"]
                }
            }
        })
        structured_logs.append(structured_line)

    return structured_logs


def send_entry(s, log_entry):
    # The log_entry can only be a string or a dict
    if isinstance(log_entry, str):
        log_entry = {"message": log_entry}
    elif not isinstance(log_entry, dict):
        raise Exception(
                "Cannot send the entry as it must be either a string or a dict. Provided entry: " + str(log_entry))

    # Merge with metadata
    log_entry = merge_dicts(log_entry, metadata)

    # Send to Logmatic.io
    str_entry = json.dumps(log_entry)
    s.send((logmaticKey + " " + str_entry + "\n").encode("UTF-8"))


def merge_dicts(a, b, path=None):
    if path is None: path = []
    for key in b:
        if key in a:
            if isinstance(a[key], dict) and isinstance(b[key], dict):
                merge_dicts(a[key], b[key], path + [str(key)])
            elif a[key] == b[key]:
                pass  # same leaf value
            else:
                raise Exception(
                        'Conflict while merging metadatas and the log entry at %s' % '.'.join(path + [str(key)]))
        else:
            a[key] = b[key]
    return a


def is_cloudtrail(key):
    regex = re.compile('\d+_CloudTrail_\w{2}-\w{4,9}-[12]_\d{8}T\d{4}Z.+.json.gz$', re.I)
    match = regex.search(key)
    return bool(match)
