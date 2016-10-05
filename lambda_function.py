from __future__ import print_function

import json
import urllib
import boto3
import socket
import ssl
import re
import zlib

#Parameters
logmaticKey = "<your_api_key>"
metadata = {"aws":{"type": "s3_logs"}}

#Constants
host = "api.logmatic.io"
port = 10514

#SSL security
#SSL security can be enabled if the certificate is zipped along with this piece of code
#while creating the lambda function
enable_security = True
ssl_port = 10515

def lambda_handler(event, context):
    if logmaticKey=="<your_api_key>":
        raise Exception("You must configure your API key before starting this lambda function (see #Parameters section)")

    #Attach Logmatic.io's Socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    if enable_security:
        s = ssl.wrap_socket(s)
        port = ssl_port

    s.connect((host, port))

    s3 = boto3.client('s3')

    # Get the object from the event and show its content type
    bucket = event['Records'][0]['s3']['bucket']['name']
    key = urllib.unquote_plus(event['Records'][0]['s3']['object']['key']).decode('utf8')

    try:
        # Extract the S3 object
        response = s3.get_object(Bucket=bucket, Key=key)
        body = response['Body']
        data = body.read()

        # If the name has a .gz extension, then decompress the data
        if key[-3:] == '.gz':
            data = zlib.decompress(data, 16+zlib.MAX_WBITS)

        if is_cloudtrail(str(key)) is True:
            cloud_trail = json.loads(data)
            for event in cloud_trail['Records']:
                #Create structured object and send it
                structered_line = merge_dicts(event,{"aws": {"s3": {"bucket": bucket, "key": key}}})
                send_entry(s,structered_line)
        else:
            #The data collected should contain multiple lines
            lines = data.splitlines()

            #Send lines to Logmatic.io
            for line in lines:
                #Create structured object and send it
                structered_line = {"aws": {"s3": {"bucket": bucket, "key": key}},"message": line}
                send_entry(s,structered_line)

    except Exception as e:
        print(e)
        err_message = 'Error getting object {} from bucket {}. Exception: {}'.format(key, bucket, str(e))
        print(err_message)
        send_entry(s,err_message)
        raise e
    finally:
        s.close()

def send_entry(s, log_entry):
    #The log_entry can only be a string or a dict
    if isinstance(log_entry, str):
        log_entry = {"message": log_entry}
    elif not isinstance(log_entry, dict):
        raise Exception("Cannot send the entry as it must be either a string or a dict. Provided entry: "+str(log_entry))

    #Merge with metadata
    log_entry = merge_dicts(log_entry,metadata)

    #Send to Logmatic.io
    str_entry = json.dumps(log_entry)
    s.send(logmaticKey + " " +str_entry+"\n")

def merge_dicts(a, b, path=None):
    "merges b into a"
    if path is None: path = []
    for key in b:
        if key in a:
            if isinstance(a[key], dict) and isinstance(b[key], dict):
                merge_dicts(a[key], b[key], path + [str(key)])
            elif a[key] == b[key]:
                pass # same leaf value
            else:
                raise Exception('Conflict while merging metadatas and the log entry at %s' % '.'.join(path + [str(key)]))
        else:
            a[key] = b[key]
    return a

def is_cloudtrail(key):
    regex = re.compile('\d+_CloudTrail_\w{2}-\w{4,9}-[12]_\d{8}T\d{4}Z.+.json.gz$', re.I)
    match = regex.search(key)
    return bool(match)
