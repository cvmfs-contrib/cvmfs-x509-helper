#!/usr/bin/python

# Run this script like this:
# sudo TOKEN=/tmp/token python ../cvmfs-x509-helper/test/test_scitoken.py ./src/cvmfs_scitoken_helper 

import subprocess
import sys
import os
import json
import struct
import scitokens
import base64
import requests

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa

helper_process = None
def WriteMsg(to_write):
    to_write_packed = struct.pack('ii', 1, len(json.dumps(to_write)))
    helper_process.stdin.write(to_write_packed)
    helper_process.stdin.write(json.dumps(to_write))

def ReadMsg():
    version, msg_size = struct.unpack('ii', helper_process.stdout.read(8))
    print("Got version: {}, msg_size: {}".format(version, msg_size))
    response = json.loads(helper_process.stdout.read(msg_size))
    return response

def main():
    global helper_process

    # The first argument is the executable to run and test
    executable = sys.argv[1]

    # Execute the helper
    os.environ["CVMFS_AUTHZ_HELPER"] = "1"
    helper_process = subprocess.Popen(executable, shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)

    # Send the helper the welcome message
    handshake = {"cvmfs_authz_v1": {'debug_log': '/tmp/debug', 'syslog_level': 1}}
    WriteMsg(handshake)

    # Get the json back
    print(ReadMsg())

    demo_json = {
        "payload": {
            'scope': "read:/",
            'aud': "ANY",
        },
        "header": {
            'alg': 'RS256',
            'typ': 'JWT'
        }
    }

    data = json.dumps({
            'payload': json.dumps(demo_json['payload']),
            'header': json.dumps(demo_json['header']),
            'algorithm': 'RS256'
            })

    # Set the header so that cloudflare lets it through
    head = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.103 Safari/537.36','Content-Type': 'application/json'}

    r = requests.post("https://demo.scitokens.org/issue", data = data, headers = head)
    serialized_token = r.text

    # Set the token variable
    with open('/tmp/token', 'w') as token_file:
        token_file.write(serialized_token)
        token_file.write("\n")
    os.environ['TOKEN'] = '/tmp/token'

    membership = "https://demo.scitokens.org"
    encoded_membership = base64.urlsafe_b64encode(membership)

    request = {'cvmfs_authz_v1': {
                    'uid': os.getuid(),
                    'gid': os.getgid(),
                    'pid': os.getpid(),
                    'msgid': 3,
                    'membership': encoded_membership}
                }
    WriteMsg(request)

    print(ReadMsg())


if __name__ == "__main__":
    main()
