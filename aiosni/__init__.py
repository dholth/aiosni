#!/usr/bin/env python
"""
SNI + acme-tls/1 responder
"""

import ssl
import pathlib

import asyncio

from asyncio.base_events import Server
from asyncio.protocols import Protocol
from asyncio.sslproto import SSLProtocol
from asyncio.transports import Transport

ACME_TLS_1 = b"acme-tls/1"

# OpenSSL has no way to get at the ALPN data
# before sni_callback and asyncio has no way to
# customize SSLProtocol. Monkey patch to capture
# raw handshake data. Would also be possible to
# construct our own factory for SSLProtocol and
# pass that into a non-ssl create_server().
_data_received = SSLProtocol.data_received


def show_data_received(self, data):
    if self._in_handshake and ACME_TLS_1 in data:
        # leave note for sni_callback
        self._sslpipe._sslobj._probably_acme = True
    return _data_received(self, data)


SSLProtocol.data_received = show_data_received


class SSLObject(ssl.SSLObject):
    _probably_acme = False  # __init__ is not called, just SSLObject()._create


class ByeProtocol(Protocol):
    def connection_made(self, transport: Transport):
        print(transport.__dict__)
        # if it's acme_tls_1, we should say goodbye immediately

    def data_received(self, data):
        print("got data", data)

    def eof_received(self):
        return


def sni_callback(sslobject: SSLObject, hostname, sslcontext):
    """
    Note that HTTP HOST header doesn't have to be the same as hostname
    """
    if hostname:
        sslobject.context = context_for_servername(hostname, sslobject._probably_acme)


acme_dir = pathlib.Path("./certificates/acme").resolve()
certs_dir = pathlib.Path("./certificates").resolve()


def context_for_servername(hostname, acme=False):
    """
    Find the appropriate acme or regular certificate for hostname.
    """
    print("load cert for", hostname)
    context = create_context()
    if acme:
        certPath = acme_dir / (f"{hostname}.crt")
        keyPath = acme_dir / (f"{hostname}.key")
        context.load_cert_chain(certfile=certPath, keyfile=keyPath)
    else:
        certPath = certs_dir / (f"{hostname}.pem")
        context.load_cert_chain(certfile=certPath)
    return context


def create_context():
    """
    Create a ssl context with our preferred defaults
    """
    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_COMPRESSION
    ssl_context.set_ciphers("ECDHE+AESGCM")
    ssl_context.sslobject_class = SSLObject  # 3.7 or change wrap_bio
    return ssl_context


ssl_context = create_context()
ssl_context.set_alpn_protocols(["http/1.1", ACME_TLS_1.decode("ascii")])
ssl_context.sni_callback = sni_callback
# may work without any cert_chain when we set one in sni_callback:
ssl_context.load_cert_chain(certfile=certs_dir / "DEFAULT.pem")


loop = asyncio.get_event_loop()
# Each client connection will create a new protocol instance
coro: Server = loop.create_server(ByeProtocol, "::", 8444, ssl=ssl_context)
server = loop.run_until_complete(coro)

# Serve requests until Ctrl+C is pressed
print("Serving on {}".format(server.sockets[0].getsockname()))
try:
    loop.run_forever()
except KeyboardInterrupt:
    pass

# Close the server
server.close()
loop.run_until_complete(server.wait_closed())
loop.close()
