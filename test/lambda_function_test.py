import socket
import unittest
import json
from pprint import pprint

import lambda_function

# Loading datasets

with open('resources/s3-put-event.json') as data_file:
    s3_data = json.load(data_file)

with open('resources/awslogs-event.json') as data_file:
    awslogs_data = json.load(data_file)


# Attach Logmatic.io's Socket
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


s.connect(("api.logmatic.io", 10514))


class TestsLambda(unittest.TestCase):
    def test_event_type_s3(self):
        self.assertEqual(lambda_function.parse_event_type(s3_data), "s3")
        self.assertEqual(lambda_function.parse_event_type(awslogs_data), "awslogs")

    def test_s3_event(self):
        # todo
        pass

    def test_awslogs_event(self):
         lambda_function.awslogs_handler(s, awslogs_data)



if __name__ == '__main__':
    unittest.main()
