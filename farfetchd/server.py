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
import copy
import json
import sys
import os.path

from twisted.python import failure, log
from twisted.python.compat import intToBytes
from twisted.internet import reactor
from twisted.web import http, server, resource
from twisted.web.util import redirectTo

import crypto
import captcha



FARFETCHD_API_VERSION = "0.0.1"
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
        if data:
            rendered = json.dumps(data)
        else:
            rendered = b""

        request.responseHeaders.addRawHeader(b"Content-Type", b"application/vnd.api+json")

        return rendered

    def render_GET(self, request):
        request.responseHeaders.setRawHeaders(b"Content-Type", ["text/html"])

        data = bytes()
        spec = os.path.sep.join([os.path.dirname(__file__), 'API.html'])

        with open(spec) as fh:
            data += bytes(fh.read())

        return data


class CaptchaFetchResource(CaptchaResource):
    """A resource to retrieve a CAPTCHA challenge."""

    isLeaf = True
    responseType = "fetch"

    def __init__(self, hmacKey=None, publicKey=None, secretKey=None,
                 captchaDir="captchas", useForwardedHeader=True):
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
            "version": FARFETCHD_API_VERSION,
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


#class FarfetchdRequestHandler(http.Request):
class FarfetchdRequestHandler(server.Request):
    """Handler for dispatching Farfetchd-specific requests."""

    #: The root resource, optionally with children
    resource = None

    def __init__(self, *args, **kwargs):
        http.Request.__init__(self, *args, **kwargs)

    def checkRequestHeaders(self):
        """The JSON API specification requires servers to respond with certain HTTP
        status codes and message if the client's request headers are inappropriate in
        any of the following ways:

        * Servers MUST respond with a 415 Unsupported Media Type status code if
          a request specifies the header Content-Type: application/vnd.api+json
          with any media type parameters.

        * Servers MUST respond with a 406 Not Acceptable status code if a
          request’s Accept header contains the JSON API media type and all
          instances of that media type are modified with media type parameters.
        """
        supports_json_api = False

        if self.requestHeaders.hasHeader("Content-Type"):
            for header in self.requestHeaders.getHeader("Content-Type"):
                # The request must have the Content-Type set to 'application/vnd.api+json':
                if header is 'application/vnd.api+json':
                    supports_json_api = True
                # The request must not specify a Content-Type with media parameters:
                if ';' in header:
                    supports_json_api = False

        if not supports_json_api:
            self.setResponseCode(http.UNSUPPORTED_MEDIA_TYPE)
            self.write(b"")
            return

        # If the request has an Accept header which contains
        # 'application/vnd.api+json' then at least one instance of that type
        # must have no parameters:
        if self.requestHeaders.hasHeader("Accept"):
            compatible_accept_header = False
            for header in self.requestHeaders.getHeader("Accept"):
                if header is 'application/vnd.api+json':
                    compatible_accept_header = True
            if not compatible_accept_header:
                self.setResponseCode(http.NOT_ACCEPTABLE)
                self.write(b"")
                return

    def process(self):
        """Process an incoming request to the Farfetchd server."""
        # Get site from channel
        self.site = self.channel.site

        # Set various default headers
        self.setHeader(b"Content-Type", b"application/vnd.api+json")
        self.setHeader(b"Server", "Farfetchd v%s" % FARFETCHD_API_VERSION)
        self.setHeader(b"Date", http.datetimeToString())

        # Resource Identification
        self.prepath = []
        self.postpath = list(map(http.unquote, self.path[1:].split(b'/')))

        log.msg("postpath is %s" % self.postpath)
        log.msg("self.resource is %s" % self.resource)

        #requested_resource = self.resource.getChildForRequest(self)
        requested_resource = resource.getChildForRequest(self.resource, self)

        try:
            requested_resource = self.site.getResourceFor(self)
            #self.render(requested_resource)
            log.msg("Requested resource is %s" % requested_resource)
            log.msg("Requested resource entities are %s" % requested_resource.listEntities())
            if requested_resource:
                if requested_resource.responseType:
                    log.msg("Request will be handled by %r" % requested_resource.__class__.__name__)
                    self.checkRequestHeaders()
                #requested_resource.render(self)
                self.render(requested_resource)
            else:
                self.setResponseCode(http.NOT_FOUND)
                self.write(b"No such resource")
        except:
            self.processingFailed(failure.Failure())

        if not self.finished:
            self.finish()

    def processingFailed(self, reason):
        log.err(reason)

        body = (b"<html><head><title>Processing Failed</title></head><body>"
                b"<b>Processing Failed</b></body></html>")

        self.setResponseCode(http.INTERNAL_SERVER_ERROR)
        self.setHeader(b'content-type', b"text/html")
        self.setHeader(b'content-length', intToBytes(len(body)))
        self.write(body)
        self.finish()
        return reason


class HttpJsonApi(http.HTTPChannel):
    """An HTTP API that responds to requests with HTTP status codes required by the
    JSON API specification.
    """
    requestFactory = FarfetchdRequestHandler


class HttpJsonApiFactory(http.HTTPFactory):
    """Factory for generating `HttpJsonApi`s."""

    _protocol = HttpJsonApi

    def buildProtocol(self, addr):
        protocol = self._protocol()
        protocol.timeout = self.timeOut
        return protocol


class HttpJsonApiServer(HttpJsonApiFactory):
    """A web application which speaks JSON API over HTTP.

    :ivar factory: A factory for the protocol we speak.
    :ivar requestFactory: factory creating requests objects. Default to
        Request}.
    :ivar displayTracebacks: if set, Twisted internal errors are displayed on
        rendered pages. Default to `True`
    """
    factory = HttpJsonApiFactory
    requestFactory = HttpJsonApiFactory._protocol.requestFactory
    displayTracebacks = True

    def __init__(self, resource, *args, **kwargs):
        """
        :param resource: The root of the resource hierarchy.  All request
            traversal for requests received by this factory will begin at this
            resource.
        :type resource: `IResource` provider

        :see: `twisted.web.http.HTTPFactory.__init__`
        """
        self.factory.__init__(self, *args, **kwargs)
        self.resource = resource
        self.requestFactory.resource = resource

    def buildProtocol(self, addr):
        """Generate an HTTP channel attached to this site."""
        channel = self.factory.buildProtocol(self, addr)
        channel.requestFactory = self.requestFactory
        channel.site = self
        return channel

    ###########################################################################
    # The remainder of the server implementation implements emulating         #
    # behaving like the root resource of the server, and passing through      #
    # requests to their responsible handlers.                                 #
    ###########################################################################

    isLeaf = False

    def render(self, request):
        """Redirect because a server represents merely the root URL."""
        request.redirect(request.prePathURL() + b'/')
        request.finish()

    def getChildWithDefault(self, pathEl, request):
        """Emulate a resource's getChild() method."""
        request.site = self
        log.msg("server.resource is %s" % self.resource)
        return self.resource.getChildWithDefault(pathEl, request)

    # XXXX problem is likely here
    def getResourceFor(self, request):
        """Get a resource for a request.

        This iterates through the resource heirarchy, calling
        getChildWithDefault on each resource it finds for a path element,
        stopping when it hits an element where isLeaf is true.
        """
        log.msg("Request for resource at %s" % request.path)

        request.site = self
        # Sitepath is used to determine cookie names between distributed
        # servers and disconnected sites.
        request.sitepath = copy.copy(request.prepath)
        child = resource.getChildForRequest(self.resource, request)
        log.msg(child)
        return child


def main():
    log.startLogging(sys.stdout)

    captchaKey = crypto.getKey(FARFETCHD_CAPTCHA_HMAC_KEYFILE)
    hmacKey = crypto.getHMAC(captchaKey, "Captcha-Key")

    # Load or create our encryption keys:
    secretKey, publicKey = crypto.getRSAKey(FARFETCHD_CAPTCHA_RSA_KEYFILE)

    index = CaptchaResource()
    #index = resource.Resource()
    fetch = CaptchaFetchResource(hmacKey, publicKey, secretKey)
    check = CaptchaCheckResource(hmacKey, publicKey, secretKey)

    root = index
    root.putChild("fetch", fetch)
    root.putChild("check", check)

    site = HttpJsonApiServer(root)
    port = FARFETCHD_HTTP_PORT or 80
    host = FARFETCHD_HTTP_HOST or '127.0.0.1'

    reactor.listenTCP(port, site, interface=host)
    reactor.run()


if __name__ == "__main__":
    main()
