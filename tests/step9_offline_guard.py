"""Child-process guard for the offline regression gate; no production imports."""

# Support direct execution from scripts/ or tests/ as well as manage.py.
import sys as _sys
from pathlib import Path as _Path
_sys.path.insert(0,str(_Path(__file__).resolve().parents[1]))
from project_paths import ROOT, activate as _activate
_activate()
import ipaddress
import os
import socket


def install():
    if getattr(socket, '_sentinelops_offline', False):
        return
    socket._sentinelops_offline = True
    original_connect = socket.socket.connect
    original_connect_ex = socket.socket.connect_ex
    original_dns = socket.getaddrinfo

    def permitted(address):
        if not isinstance(address, tuple):
            return True  # Local Unix-domain IPC on platforms supporting it.
        host = address[0]
        try:
            return ipaddress.ip_address(host).is_loopback
        except ValueError:
            return host == 'localhost'

    def connect(sock, address):
        if not permitted(address):
            raise PermissionError('External network disabled by Step 9 offline gate')
        return original_connect(sock, address)

    def connect_ex(sock, address):
        if not permitted(address):
            raise PermissionError('External network disabled by Step 9 offline gate')
        return original_connect_ex(sock, address)

    def dns(host, *args, **kwargs):
        if host is not None and not permitted((host, 0)):
            raise PermissionError('External DNS disabled by Step 9 offline gate')
        return original_dns(host, *args, **kwargs)

    original_sendto = socket.socket.sendto

    def sendto(sock, data, *args):
        if args and not permitted(args[-1]):
            raise PermissionError('External datagrams disabled by Step 9 offline gate')
        return original_sendto(sock, data, *args)

    socket.socket.connect = connect
    socket.socket.connect_ex = connect_ex
    socket.socket.sendto = sendto
    socket.getaddrinfo = dns


if os.environ.get('SENTINELOPS_OFFLINE_GATE') == '1':
    install()
