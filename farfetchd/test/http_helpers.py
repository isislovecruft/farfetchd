# -*- coding: utf-8 -*-
#_____________________________________________________________________________
#
# This file is part of farfetchd, a CAPTCHA service
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
# :copyright: (c) 2017, Isis Lovecruft
#             (c) 2017, The Tor Project, Inc.
# :license: see LICENSE for licensing information
#_____________________________________________________________________________


"""Helpers for testing the HTTP server."""


import io

from twisted.internet.defer import Deferred
from twisted.internet.address import IPv4Address
from twisted.web.http_headers import Headers
from twisted.web.server import NOT_DONE_YET, Session
from twisted.web.test import requesthelper

class RequestHelperDummyRequest(object):
    """
    Represents a dummy or fake request.

    Taken from Twisted-14.0.2 because this helper class changed in 16.0.0.

    @ivar _finishedDeferreds: C{None} or a C{list} of L{Deferreds} which will
        be called back with C{None} when C{finish} is called or which will be
        errbacked if C{processingFailed} is called.

    @type headers: C{dict}
    @ivar headers: A mapping of header name to header value for all request
        headers.

    @type outgoingHeaders: C{dict}
    @ivar outgoingHeaders: A mapping of header name to header value for all
        response headers.

    @type responseCode: C{int}
    @ivar responseCode: The response code which was passed to
        C{setResponseCode}.

    @type written: C{list} of C{bytes}
    @ivar written: The bytes which have been written to the request.
    """
    uri = b'http://dummy/'
    method = b'GET'
    client = None

    def registerProducer(self, prod,s):
        self.go = 1
        while self.go:
            prod.resumeProducing()

    def unregisterProducer(self):
        self.go = 0


    def __init__(self, postpath, session=None):
        self.sitepath = []
        self.written = []
        self.finished = 0
        self.postpath = postpath
        self.prepath = []
        self.session = None
        self.protoSession = session or Session(0, self)
        self.args = {}
        self.outgoingHeaders = {}
        self.requestHeaders = Headers()
        self.responseHeaders = Headers()
        self.responseCode = None
        self.headers = {}
        self._finishedDeferreds = []
        self._serverName = b"dummy"
        self.clientproto = b"HTTP/1.0"

    def getHeader(self, name):
        """
        Retrieve the value of a request header.

        @type name: C{bytes}
        @param name: The name of the request header for which to retrieve the
            value.  Header names are compared case-insensitively.

        @rtype: C{bytes} or L{NoneType}
        @return: The value of the specified request header.
        """
        return self.headers.get(name.lower(), None)


    def getAllHeaders(self):
        """
        Retrieve all the values of the request headers as a dictionary.

        @return: The entire C{headers} L{dict}.
        """
        return self.headers


    def setHeader(self, name, value):
        """TODO: make this assert on write() if the header is content-length
        """
        self.outgoingHeaders[name.lower()] = value

    def getSession(self):
        if self.session:
            return self.session
        assert not self.written, "Session cannot be requested after data has been written."
        self.session = self.protoSession
        return self.session


    def render(self, resource):
        """
        Render the given resource as a response to this request.

        This implementation only handles a few of the most common behaviors of
        resources.  It can handle a render method that returns a string or
        C{NOT_DONE_YET}.  It doesn't know anything about the semantics of
        request methods (eg HEAD) nor how to set any particular headers.
        Basically, it's largely broken, but sufficient for some tests at least.
        It should B{not} be expanded to do all the same stuff L{Request} does.
        Instead, L{DummyRequest} should be phased out and L{Request} (or some
        other real code factored in a different way) used.
        """
        result = resource.render(self)
        if result is NOT_DONE_YET:
            return
        self.write(result)
        self.finish()


    def write(self, data):
        if not isinstance(data, bytes):
            raise TypeError("write() only accepts bytes")
        self.written.append(data)

    def notifyFinish(self):
        """
        Return a L{Deferred} which is called back with C{None} when the request
        is finished.  This will probably only work if you haven't called
        C{finish} yet.
        """
        finished = Deferred()
        self._finishedDeferreds.append(finished)
        return finished


    def finish(self):
        """
        Record that the request is finished and callback and L{Deferred}s
        waiting for notification of this.
        """
        self.finished = self.finished + 1
        if self._finishedDeferreds is not None:
            observers = self._finishedDeferreds
            self._finishedDeferreds = None
            for obs in observers:
                obs.callback(None)


    def processingFailed(self, reason):
        """
        Errback and L{Deferreds} waiting for finish notification.
        """
        if self._finishedDeferreds is not None:
            observers = self._finishedDeferreds
            self._finishedDeferreds = None
            for obs in observers:
                obs.errback(reason)


    def addArg(self, name, value):
        self.args[name] = [value]


    def setResponseCode(self, code, message=None):
        """
        Set the HTTP status response code, but takes care that this is called
        before any data is written.
        """
        assert not self.written, "Response code cannot be set after data has been written: %s." % "@@@@".join(self.written)
        self.responseCode = code
        self.responseMessage = message


    def setLastModified(self, when):
        assert not self.written, "Last-Modified cannot be set after data has been written: %s." % "@@@@".join(self.written)


    def setETag(self, tag):
        assert not self.written, "ETag cannot be set after data has been written: %s." % "@@@@".join(self.written)


    def getClientIP(self):
        """
        Return the IPv4 address of the client which made this request, if there
        is one, otherwise C{None}.
        """
        if isinstance(self.client, IPv4Address):
            return self.client.host
        return None


    def getRequestHostname(self):
        """
        Get a dummy hostname associated to the HTTP request.

        @rtype: C{bytes}
        @returns: a dummy hostname
        """
        return self._serverName


    def getHost(self):
        """
        Get a dummy transport's host.

        @rtype: C{IPv4Address}
        @returns: a dummy transport's host
        """
        return IPv4Address('TCP', '127.0.0.1', 80)


    def getClient(self):
        """
        Stub to get the client doing the HTTP request.
        This merely just ensures that this method exists here. Feel free to
        extend it.
        """


class DummyRequest(RequestHelperDummyRequest):
    """Wrapper for :api:`twisted.test.requesthelper.DummyRequest` to add
    redirect support.
    """
    def __init__(self, *args, **kwargs):
        RequestHelperDummyRequest.__init__(self, *args, **kwargs)
        self.redirect = self._redirect(self)
        self.content = io.StringIO()

        self.headers = {}  # Needed for Twisted>14.0.2
        #self.outgoingHeaders = {}
        #self.responseHeaders = Headers()
        #self.requestHeaders = Headers()

    def writeContent(self, data):
        """Add some **data** to the faked body of this request.

        This is useful when testing how servers handle content from POST
        requests.

        .. warn: Calling this method multiple times will overwrite any data
            previously written.

        :param str data: Some data to put in the "body" (i.e. the
            :attr:`content`) of this request.
        """
        try:
            self.content.write(type(u'')(data))
        except UnicodeDecodeError:
            self.content.write(type(u'')(data, 'utf-8'))
        finally:
            self.content.flush()
            self.content.seek(0)

    def URLPath(self):
        """Fake the missing Request.URLPath too."""
        return self.uri

    def _redirect(self, request):
        """Stub method to add a redirect() method to DummyResponse."""
        newRequest = type(request)
        newRequest.uri = request.uri
        return newRequest


#DummyRequest = RequestHelperDummyRequest
