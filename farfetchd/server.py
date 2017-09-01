#!/usr/bin/env python2
# -*- coding: utf-8 -*-
#_____________________________________________________________________________
#
# This file is part of farfetchd, a server for CAPTCHA challenge creation and
# response verification.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
# :copyright: (c) 2013-2017, Isis Lovecruft
#             (c) 2007-2017, The Tor Project, Inc.
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

"""An HTTP server for serving CAPTCHAs."""

import base64
import json
import sys

from twisted.python import log
from twisted.internet import reactor
from twisted.web import server, resource
from twisted.web.util import redirectTo

import crypto
import captcha


FARFETCHD_PROTOCOL_VERSION = 1
FARFETCHD_HTTP_HOST = '127.0.0.1'
FARFETCHD_HTTP_PORT = 3888
FARFETCHD_CAPTCHA_HMAC_KEYFILE = 'farfetchd-key-hmac'
FARFETCHD_CAPTCHA_RSA_KEYFILE = 'farfetchd-key-rsa'


def getClientIP(request, useForwardedHeader=False):
    """Get the client's IP address from the ``'X-Forwarded-For:'``
    header, or from the :api:`request <twisted.web.server.Request>`.

    :type request: :api:`twisted.web.http.Request`
    :param request: A ``Request`` for a :api:`twisted.web.resource.Resource`.
    :param bool useForwardedHeader: If ``True``, attempt to get the client's
        IP address from the ``'X-Forwarded-For:'`` header.
    :rtype: ``None`` or :any:`str`
    :returns: The client's IP address, if it was obtainable.
    """
    ip = None

    if useForwardedHeader:
        header = request.getHeader("X-Forwarded-For")
        if header:
            ip = header.split(",")[-1].strip()
            if not isIPAddress(ip):
                log.msg("Got weird X-Forwarded-For value %r" % header)
                ip = None
    else:
        ip = request.getClientIP()

    return ip


class CaptchaResource(resource.Resource):
    """A CAPTCHA."""

    responseType = ""

    def __init__(self, hmacKey=None, publicKey=None, secretKey=None,
                 useForwardedHeader=False):
        resource.Resource.__init__(self)
        self.hmacKey = hmacKey
        self.publicKey = publicKey
        self.secretKey = secretKey
        self.useForwardedHeader = useForwardedHeader

    def getClientIP(self, request):
        """Get the client's IP address from the ``'X-Forwarded-For:'``
        header, or from the :api:`request <twisted.web.server.Request>`.

        :type request: :api:`twisted.web.http.Request`
        :param request: A ``Request`` for a
            :api:`twisted.web.resource.Resource`.
        :rtype: ``None`` or :any:`str`
        :returns: The client's IP address, if it was obtainable.
        """
        return getClientIP(request, self.useForwardedHeader)

    def formatResponse(self, data, request):
        """Format a dictionary of ``data`` into JSON and add necessary response
        headers.

        This method will set the appropriate response headers:
            * `Content-Type: application/vnd.api+json`

        :type data: dict
        :param data: Some data to respond with.  This will be formatted as JSON.
        :returns: The encoded data.
        """
        rendered = json.dumps(data)
        request.responseHeaders.addRawHeader(b"Content-Type", b"application/vnd.api+json")
        return rendered


class CaptchaFetchResource(CaptchaResource):
        """A resource to retrieve a CAPTCHA challenge."""

    isLeaf = True
    responseType = "fetch"

    def __init__(self, hmacKey=None, publicKey=None, secretKey=None,
                 captchaDir="captchas", useForwardedHeader=False):
        CaptchaResource.__init__(self, hmacKey, publicKey, secretKey,
                                 useForwardedHeader)
        self.captchaDir = captchaDir

    def getCaptchaImage(self, request):
        """Get a random CAPTCHA image from our **captchaDir**.

        Creates a :class:`~farfetchd.captcha.GimpCaptcha`, and calls its
        :meth:`~farfetchd.captcha.GimpCaptcha.get` method to return a random
        CAPTCHA and challenge string.

        :type request: :api:`twisted.web.http.Request`
        :param request: A client's initial request for some other resource
            which is protected by this one (i.e. protected by a CAPTCHA).
        :returns: A 2-tuple of ``(image, challenge)``, where::
            - ``image`` is a string holding a binary, JPEG-encoded image.
            - ``challenge`` is a unique string associated with the request.
        """
        # Create a new HMAC key, specific to requests from this client:
        clientIP = self.getClientIP(request)
        clientHMACKey = crypto.getHMAC(self.hmacKey, clientIP)
        capt = captcha.GimpCaptcha(self.publicKey, self.secretKey,
                                   clientHMACKey, self.captchaDir)
        try:
            capt.get()
        except captcha.GimpCaptchaError as error:
            log.error(error)
        except Exception as error:  # pragma: no cover
            log.error("Unhandled error while retrieving Gimp captcha!")
            log.error(error)

        return (capt.image, capt.challenge)

    def render_GET(self, request):
        """Retrieve a ReCaptcha from the API server and serve it to the client.

        :type request: :api:`twisted.web.http.Request`
        :param request: A ``Request`` object for a CAPTCHA.
        :rtype: str
        :returns: A JSON blob containing the following fields:
             * "version": The Farfetchd protocol version.
             * "image": A base64-encoded CAPTCHA JPEG image.
             * "challenge": A base64-encoded, encrypted challenge.  The client
               will need to hold on to the and pass it back later, along with
               their challenge response.
             * "error": An ASCII error message.
            Any of the above JSON fields may be "null".
        """
        image, challenge = self.getCaptchaImage(request)

        data = {
            "version": FARFETCHD_PROTOCOL_VERSION,
            "type": self.responseType,
        }

        try:
            data["image"] = base64.b64encode(image)
            data["challenge"] = challenge, # The challenge is already base64-encoded.
            data["error"] = None
        except Exception as err:
            data["image"] = None
            data["challenge"] = None
            data["error"] = "Could not construct or encode captcha!"

        return self.prepareResponse(data, request)

    def render_POST(self, request):
        data = {
            "version": FARFETCHD_PROTOCOL_VERSION,
            "type": self.responseType,
            "image": None,
            "challenge": None,
            "error": "Requests to %s must be GET requests." % request.uri,
        }
        return self.prepareResponse(data, request)


class CaptchaCheckResource(CaptchaResource):
    """A resource to verify a CAPTCHA solution."""

    isLeaf = True
    responseType = "check"

    def __init__(self, hmacKey=None, publicKey=None, secretKey=None,
                 useForwardedHeader=False):
        CaptchaResource.__init__(self, hmacKey, publicKey, secretKey,
                                 useForwardedHeader)

    def extractClientSolution(self, request):
        """Extract the client's CAPTCHA solution from a POST request.

        This is used after receiving a POST request from a client (which
        should contain their solution to the CAPTCHA), to extract the solution
        and challenge strings.

        :type request: :api:`twisted.web.http.Request`
        :param request: A ``Request`` to verify a CAPTCHA.
        :returns: A redirect for a request for a new CAPTCHA if there was a
            problem. Otherwise, returns a 2-tuple of strings, the first is the
            client's CAPTCHA solution from the text input area, and the second
            is the challenge string.
        """
        try:
            encoded_data = request.args['data'][0]
            data = json.loads(encoded_data)
            challenge = data["challenge"]
            response = data["response"]
        except Exception:  # pragma: no cover
            return redirectTo(request.URLPath(), request)

        return (challenge, response)

    def checkSolution(self, request):
        """Process a solved CAPTCHA via
        :meth:`farfetchd.captcha.GimpCaptcha.check`.

        :type request: :api:`twisted.web.http.Request`
        :param request: A ``Request`` object, including POST arguments which
            should include two key/value pairs: one key being
            ``'captcha_challenge_field'``, and the other,
            ``'captcha_response_field'``. These POST arguments should be
            obtained from :meth:`render_GET`.
        :rtupe: bool
        :returns: True, if the CAPTCHA solution was valid; False otherwise.
        """
        valid = False
        challenge, solution = self.extractClientSolution(request)
        clientIP = self.getClientIP(request)
        clientHMACKey = crypto.getHMAC(self.hmacKey, clientIP)

        try:
            valid = captcha.GimpCaptcha.check(challenge, solution,
                                              self.secretKey, clientHMACKey)
        except captcha.CaptchaExpired as error:
            log.error(error)
            valid = False

        log.msg("%sorrect captcha from %r: %r."
                % ("C" if valid else "Inc", clientIP, solution))
        return valid

    def render_GET(self, request):
        data = {
            "version": FARFETCHD_PROTOCOL_VERSION,
            "type": self.responseType,
            "result": None,
            "error": "Requests to %s must be POST requests." % request.uri,
        }
        return self.prepareResponse(data, request)

    def render_POST(self, request):
        """Process a client's CAPTCHA solution.

        If the client's CAPTCHA solution is valid (according to
        :meth:`checkSolution`), process and serve their original
        request. Otherwise, redirect them back to a new CAPTCHA page.

        :type request: :api:`twisted.web.http.Request`
        :param request: A ``Request`` object, including POST arguments which
            should include two key/value pairs: one key being
            ``'captcha_challenge_field'``, and the other,
            ``'captcha_response_field'``. These POST arguments should be
            obtained from :meth:`render_GET`.
        :rtype: str
        :returns: A rendered HTML page containing a ReCaptcha challenge image
            for the client to solve.
        """
        data = {
            "version": FARFETCHD_PROTOCOL_VERSION,
            "type": self.responseType,
            "result": False,
            "error": None,
        }

        if self.checkSolution(request) is True:
            try:
                data["result"] = True
            except Exception as err:
                data["result"] = False
                data["error"] = bytes(err.message)
        else:
            log.msg("Client failed a CAPTCHA; returning redirect to /fetch")
            return redirectTo("/fetch", request)

        return self.prepareResponse(data, request)


def main():
    log.startLogging(sys.stdout)

    captchaKey = crypto.getKey(FARFETCHD_CAPTCHA_HMAC_KEYFILE)
    hmacKey = crypto.getHMAC(captchaKey, "Captcha-Key")

    # Load or create our encryption keys:
    secretKey, publicKey = crypto.getRSAKey(FARFETCHD_CAPTCHA_RSA_KEYFILE)

    fetch = CaptchaFetchResource(hmacKey, publicKey, secretKey)
    check = CaptchaCheckResource(hmacKey, publicKey, secretKey)

    root = CaptchaResource()
    root.putChild("fetch", fetch)
    root.putChild("check", check)

    site = server.Site(root)
    port = FARFETCHD_HTTP_PORT or 80
    host = FARFETCHD_HTTP_HOST or '127.0.0.1'

    reactor.listenTCP(port, site, interface=host)
    reactor.run()


if __name__ == "__main__":
    main()
