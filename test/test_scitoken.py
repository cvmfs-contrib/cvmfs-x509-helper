#!/usr/bin/python

# Run this script like this:
# sudo TOKEN=/tmp/token python ../cvmfs-x509-helper/test/test_scitoken.py ./src/cvmfs_scitoken_helper 

import subprocess
import sys
import os
import json
import struct

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
    
    # Set the token variable
    with open('/tmp/token', 'w') as token_file:
        token_file.write("abcd1234")
    os.environ['TOKEN'] = '/tmp/token'
    
    request = {'cvmfs_authz_v1': {
                    'uid': os.getuid(),
                    'gid': os.getgid(),
                    'pid': os.getpid(),
                    'msgid': 3,
                    'membership': ""}
                }
    WriteMsg(request)
    
    print(ReadMsg())
    


if __name__ == "__main__":
    main()




