# -*- coding: utf-8 -*-
#
# This file is part of farfetchd, a CAPTCHA service
#
# :authors: Isis Lovecruft <isis@torproject.org>
# :copyright: (c) 2007-2017, The Tor Project, Inc.
#             (c) 2013-2017, Isis Lovecruft
# :license: 3-clause BSD, see included LICENSE for information

"""This module contains general utilities for working with external
cryptographic tools and libraries, including OpenSSL. It also
includes utilities for creating callable HMAC functions, generating HMACs for
data, and generating and/or storing key material.
"""

from __future__ import absolute_import
from __future__ import unicode_literals

import hashlib
import hmac
import io
import logging
import os

import OpenSSL

from Crypto.Cipher import PKCS1_OAEP
from Crypto.PublicKey import RSA


#: The hash digest to use for HMACs.
DIGESTMOD = hashlib.sha1

# Test to see if we have the old or new style buffer() interface. Trying
# to use an old-style buffer on Python2.7 prior to version 2.7.5 will produce:
#
#     TypeError: 'buffer' does not have the buffer interface
#
#: ``True`` if we have the new-style `buffer`_ interface; ``False`` otherwise.
#:
#: .. _buffer: https://docs.python.org/2/c-api/buffer.html
NEW_BUFFER_INTERFACE = False
try:
    io.BytesIO(buffer('test'))
except TypeError:  # pragma: no cover
    logging.warn((
        "This Python version is too old! It doesn't support new-style buffer"
        "interfaces: https://mail.python.org/pipermail/python-dev/"
        "2010-October/104917.html"))
else:
    NEW_BUFFER_INTERFACE = True


class PKCS1PaddingError(Exception):
    """Raised when there is a problem adding or removing PKCS#1 padding."""

class RSAKeyGenerationError(Exception):
    """Raised when there was an error creating an RSA keypair."""


def writeKeyToFile(key, filename):
    """Write **key** to **filename**, with ``0400`` permissions.

    If **filename** doesn't exist, it will be created. If it does exist
    already, and is writable by the owner of the current process, then it will
    be truncated to zero-length and overwritten.

    :param bytes key: A key (or some other private data) to write to
        **filename**.
    :param str filename: The path of the file to write to.
    :raises: Any exceptions which may occur.
    """
    logging.info("Writing key to file: %r", filename)
    flags = os.O_WRONLY | os.O_TRUNC | os.O_CREAT | getattr(os, "O_BIN", 0)
    fd = os.open(filename, flags, 0400)
    os.write(fd, key)
    os.fsync(fd)
    os.close(fd)

def getRSAKey(filename, bits=2048):
    """Load the RSA key stored in **filename**, or create and save a new key.

    >>> from farfetchd import crypto
    >>> keyfile = 'doctest_getRSAKey'
    >>> message = "The secret words are Squeamish Ossifrage."
    >>> keypair = crypto.getRSAKey(keyfile, bits=2048)
    >>> (secretkey, publickey) = keypair
    >>> encrypted = publickey.encrypt(message)
    >>> assert encrypted != message
    >>> decrypted = secretkey.decrypt(encrypted)
    >>> assert message == decrypted


    If **filename** already exists, it is assumed to contain a PEM-encoded RSA
    private key, which will be read from the file. (The parameters of a
    private RSA key contain the public exponent and public modulus, which
    together comprise the public key ― ergo having two separate keyfiles is
    assumed unnecessary.)

    If **filename** doesn't exist, a new RSA keypair will be created, and the
    private key will be stored in **filename**, using :func:`writeKeyToFile`.

    Once the private key is either loaded or created, the public key is
    extracted from it. Both keys are then input into PKCS#1 RSAES-OAEP cipher
    schemes (see `RFC 3447 §7.1`__) in order to introduce padding, and then
    returned.

    .. __: https://tools.ietf.org/html/rfc3447#section-7.1

    :param str filename: The filename to which the secret parameters of the
        RSA key are stored in.
    :param int bits: If no key is found within the file, create a new key with
        this bitlength and store it in **filename**.
    :rtype: tuple of ``Crypto.Cipher.PKCS1_OAEP.PKCS1OAEP_Cipher``
    :returns: A 2-tuple of ``(privatekey, publickey)``, which are PKCS#1
        RSAES-OAEP padded and encoded private and public keys, forming an RSA
        keypair.
    """
    filename = os.path.extsep.join([filename, 'sec'])
    keyfile = os.path.join(os.getcwd(), filename)

    try:
        fh = open(keyfile, 'rb')
    except IOError:
        logging.info("Generating %d-bit RSA keypair...", bits)
        secretKey = RSA.generate(bits, e=65537)

        # Store a PEM copy of the secret key (which contains the parameters
        # necessary to create the corresponding public key):
        secretKeyPEM = secretKey.exportKey("PEM")
        writeKeyToFile(secretKeyPEM, keyfile)
    else:
        logging.info("Secret RSA keyfile %r found. Loading...", filename)
        secretKey = RSA.importKey(fh.read())
        fh.close()

    publicKey = secretKey.publickey()

    # Add PKCS#1 OAEP padding to the secret and public keys:
    sk = PKCS1_OAEP.new(secretKey)
    pk = PKCS1_OAEP.new(publicKey)

    return (sk, pk)

def getKey(filename):
    """Load the master key stored in ``filename``, or create a new key.

    If ``filename`` does not exist, create a new 32-byte key and store it in
    ``filename``.

    >>> import os
    >>> from farfetchd import crypto
    >>> name = 'doctest_getKey'
    >>> os.path.exists(name)
    False
    >>> k1 = crypto.getKey(name)
    >>> os.path.exists(name)
    True
    >>> open(name).read() == k1
    True
    >>> k2 = crypto.getKey(name)
    >>> k1 == k2
    True

    :param string filename: The filename to store the secret key in.
    :rtype: bytes
    :returns: A byte string containing the secret key.
    """
    try:
        fh = open(filename, 'rb')
    except IOError:
        logging.debug("getKey(): Creating new secret key.")
        key = OpenSSL.rand.bytes(32)
        writeKeyToFile(key, filename)
    else:
        logging.debug("getKey(): Secret key file found. Loading...")
        key = fh.read()
        fh.close()
    return key

def getHMAC(key, value):
    """Return the HMAC of **value** using the **key**."""
    h = hmac.new(key, value, digestmod=DIGESTMOD)
    return h.digest()

def getHMACFunc(key, hex=True):
    """Return a function that computes the HMAC of its input using the **key**.

    :param bool hex: If True, the output of the function will be hex-encoded.
    :rtype: callable
    :returns: A function which can be uses to generate HMACs.
    """
    h = hmac.new(key, digestmod=DIGESTMOD)
    def hmac_fn(value):
        h_tmp = h.copy()
        h_tmp.update(value)
        if hex:
            return h_tmp.hexdigest()
        else:
            return h_tmp.digest()
    return hmac_fn

def removePKCS1Padding(message):
    """Remove PKCS#1 padding from a **message**.

    (PKCS#1 v1.0?  See :trac:`13042`.)

    Each block is 128 bytes total in size:

        * 2 bytes for the type info (``'\\x00\\x01'``)
        * 1 byte for the separator (``'\\x00'``)
        * variable length padding (``'\\xFF'``)
        * variable length for the **message**

    .. Note that the above strings are double escaped, due to the way that
       Sphinx renders escaped strings in docstrings.

    For more information on the structure of PKCS#1 padding, see :rfc:`2313`,
    particularly `the notes in §8.1`__.

    .. __: https://tools.ietf.org/html/rfc2313#section-8.1

    :param str message: A message which is PKCS#1 padded.
    :raises PKCS1PaddingError: if there is an issue parsing the **message**.
    :rtype: bytes
    :returns: The message without the PKCS#1 padding.
    """
    padding = b'\xFF'
    typeinfo = b'\x00\x01'
    separator = b'\x00'

    unpadded = None

    try:
        if message.index(typeinfo) != 0:
            raise PKCS1PaddingError("Couldn't find PKCS#1 identifier bytes!")
        start = message.index(separator, 2) + 1  # 2 bytes for the typeinfo,
                                                 # and 1 byte for the separator.
    except ValueError:
        raise PKCS1PaddingError("Couldn't find PKCS#1 separator byte!")
    else:
        unpadded = message[start:]

    return unpadded
