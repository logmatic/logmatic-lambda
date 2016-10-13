from __future__ import print_function

import base64
import json
import urllib
import boto3
import socket
import ssl
import re
import zlib

# Parameters
logmaticKey = "<your_api_key>"

metadata = {"aws": {}}

# Constants
host = "api.logmatic.io"
raw_port = 10514

# SSL security
# SSL security can be enabled if the certificate is zipped along with this piece of code
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

    try:

        # Route to the corresponding parser
        event_type = parse_event_type(event)
        if event_type == "s3":
            s3_handler(s, event)

        elif event_type == "awslogs":
            awslogs_handler(s, event)


    except Exception as e:
        # Logs through the socket the error
        err_message = 'Error parsing the object. Exception: {}'.format(str(e))
        send_entry(s, err_message)
        raise e
    finally:
        s.close()


def parse_event_type(event):
    if "Records" in event and len(event["Records"]) > 0:
        if "s3" in event["Records"][0]:
            return "s3"
    elif "awslogs" in event:
        return "awslogs"

    raise Exception("Event type not supported (see #Event supported section)")


def s3_handler(s, event):
    s3 = boto3.client('s3')

    # Get the object from the event and show its content type
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = urllib.unquote_plus(event['Records'][0]['s3']['object']['key']).decode('utf8')

    # Extract the S3 object
    response = s3.get_object(Bucket=bucket, Key=key)
    body = response['Body']
    data = body.read()

    # If the name has a .gz extension, then decompress the data
    if key[-3:] == '.gz':
        data = zlib.decompress(data, 16 + zlib.MAX_WBITS)

    if is_cloudtrail(str(key)) is True:
        cloud_trail = json.loads(data)
        for event in cloud_trail['Records']:
            # Create structured object and send it
            structured_line = merge_dicts(event, {"aws": {"s3": {"bucket": bucket, "key": key}}})
            send_entry(s, structured_line)
    else:
        # The data collected should contain multiple lines
        lines = data.splitlines()

        # Send lines to Logmatic.io
        for line in lines:
            # Create structured object and send it
            structured_line = {"aws": {"s3": {"bucket": bucket, "key": key}}, "message": line}
            send_entry(s, structured_line)


def awslogs_handler(s, event):

    # Get logs
    logs = data_as_json(event)

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
        send_entry(s, structured_line)


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


def data_as_json(event):
    data = zlib.decompress(base64.b64decode(event["awslogs"]["data"]), 16 + zlib.MAX_WBITS)
    json_logs = json.loads(str(data))

    return json_logs
