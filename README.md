# docker-daemon-checker

Please use Python 3 to run this script.

Currently, it assumes the target system is RHEL-based and has SELinux installed on it. It will check if the daemon port is open, check the SELinux status on the host through a container, and optionally exploit the host by adding an SSH key of the user’s choosing to root’s authorized_keys. In the future, I plan to add support for systems that have AppArmor as well as systems that don’t have any sort of mandatory access control system. I also want to add the ability to scan and/or exploit multiple systems at a time.
