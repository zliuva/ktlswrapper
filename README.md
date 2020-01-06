# KTLS Wrapper [![Build Status](https://travis-ci.com/zliuva/ktlswrapper.svg?token=3u2VrXJmVG2X8YDf7p67&branch=master)](https://travis-ci.com/zliuva/ktlswrapper)[![](https://github.com/zliuva/ktlswrapper/workflows/build/badge.svg)](https://github.com/zliuva/ktlswrapper/actions?query=workflow%3Abuild)

A wrapper that enables TLS support (TLS 1.2 with AES 128 GCM) for existing applications without code change.

## Requirements

Kernel `4.17` or above, module `tls` loaded.

## Usage

```bash
LD_PRELOAD=</full/path/to/libktlswrapper.so> \
KTLS_WRAPPER_CERT=</full/path/to/tls/cert (PEM format)> \
KTLS_WRAPPER_KEY=</full/path/to/tls/private-key (PEM format)> \
KTLS_WRAPPER_PORT=<port existing application listens on> \
<existing application>
```

or any other ways to specify environment variables such as systemd unit files; be aware of `LD_PRELOAD` limitations on setuid executables.

## How does it work?

The wrapper hooks into `accept`/`accept4`. Before returning the client socket, the wrapper initiates an SSL handshake using [mbedtls](https://github.com/ARMmbed/mbedtls) and enables [Kernel TLS](https://www.kernel.org/doc/html/latest/networking/tls.html) on the socket for both sending and receiving, using the established secrets from mbedtls. Any subsequent `read`s/`write`s to the socket would have decryption and encryption working transparently.

## Why?

Why not?

## Is this safe to use on production?

~Definitely not.~ ~Maybe.~ Worse things have happened.
