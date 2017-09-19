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

"""Unittests for :mod:`farfetchd.server`."""

from __future__ import print_function

import logging
import os
import shutil

from twisted.internet import reactor
from twisted.internet import task
from twisted.trial import unittest
from twisted.web.resource import Resource
from twisted.web.test import requesthelper

from farfetchd import server

from farfetchd.test.https_helpers import DummyRequest


# For additional logger output for debugging, comment out the following:
logging.disable(50)
# and then uncomment the following line:
#server.logging.getLogger().setLevel(10)


class GetClientIPTests(unittest.TestCase):
    """Tests for :func:`bridgedb.https.server.getClientIP`."""

    def createRequestWithIPs(self):
        """Set the IP address returned from ``request.getClientIP()`` to
        '3.3.3.3', and the IP address reported in the 'X-Forwarded-For' header
        to '2.2.2.2'.
        """
        request = DummyRequest([''])
        request.headers.update({'x-forwarded-for': '2.2.2.2'})
        # See :api:`twisted.test.requesthelper.DummyRequest.getClientIP`
        request.client = requesthelper.IPv4Address('TCP', '3.3.3.3', 443)
        request.method = b'GET'
        return request

    def test_getClientIP_XForwardedFor(self):
        """getClientIP() should return the IP address from the
        'X-Forwarded-For' header when ``useForwardedHeader=True``.
        """
        request = self.createRequestWithIPs()
        clientIP = server.getClientIP(request, useForwardedHeader=True)
        self.assertEqual(clientIP, '2.2.2.2')

    def test_getClientIP_XForwardedFor_bad_ip(self):
        """getClientIP() should return None if the IP address from the
        'X-Forwarded-For' header is bad/invalid and
        ``useForwardedHeader=True``.
        """
        request = self.createRequestWithIPs()
        request.headers.update({'x-forwarded-for': 'pineapple'})
        clientIP = server.getClientIP(request, useForwardedHeader=True)
        self.assertEqual(clientIP, None)

    def test_getClientIP_fromRequest(self):
        """getClientIP() should return the IP address from the request instance
        when ``useForwardedHeader=False``.
        """
        request = self.createRequestWithIPs()
        clientIP = server.getClientIP(request)
        self.assertEqual(clientIP, '3.3.3.3')


class IndexResourceTests(unittest.TestCase):
    """Test for :class:`bridgedb.https.server.IndexResource`."""

    def setUp(self):
        self.pagename = ''
        self.indexResource = server.IndexResource()
        self.root = Resource()
        self.root.putChild(self.pagename, self.indexResource)

    def test_IndexResource_render_GET(self):
        """renderGet() should return the index page."""
        request = DummyRequest([self.pagename])
        request.method = b'GET'
        page = self.indexResource.render_GET(request)
        self.assertSubstring("add the bridges to Tor Browser", page)


class CaptchaFetchResourceTests(unittest.TestCase):
    """Tests for :mod:`farfetchd.server.CaptchaFetchResource`."""

    def setUp(self):
        """Create a :class:`CaptchaFetchResource`.
        """
        # Create our cached CAPTCHA directory:
        self.captchaDir = 'captchas'
        if not os.path.isdir(self.captchaDir):
            os.makedirs(self.captchaDir)

        # Set up our resources to fake a minimal HTTP(S) server:
        self.pagename = b'fetch'
        self.root = Resource()
        self.captchaResource = server.GimpCaptchaProtectedResource(
            secretKey='42',
            publicKey='23',
            hmacKey='abcdefghijklmnopqrstuvwxyz012345',
            captchaDir='captchas',
            useForwardedHeader=True)

        self.root.putChild(self.pagename, self.captchaResource)

        # Set up the basic parts of our faked request:
        self.request = DummyRequest([self.pagename])

    def tearDown(self):
        """Delete the cached CAPTCHA directory if it still exists."""
        if os.path.isdir(self.captchaDir):
            shutil.rmtree(self.captchaDir)

    def test_get(self):
        """Test making a GET request to /fetch."""
        self.request.method = b'GET'
        
        response = self.captchaResource.render(self.request)

        self.assertEqual(response.code, 200)
        self.assertIn('data', response)


# class CaptchaCheckResourceTests(unittest.TestCase):
#     """Tests for :mod:`farfetchd.server.CaptchaCheckResource`."""
# 
#     def test_extractClientSolution(self):
#         """A (challenge, sollution) pair extracted from a request resulting
#         from a POST should have the same unmodified (challenge, sollution) as
#         the client originally POSTed.
#         """
#         expectedChallenge = '23232323232323232323'
#         expectedResponse = 'awefawefaefawefaewf'
# 
#         self.request.method = b'POST'
#         self.request.addArg('captcha_challenge_field', expectedChallenge)
#         self.request.addArg('captcha_response_field', expectedResponse)
# 
#         response = self.captchaResource.extractClientSolution(self.request)
#         (challenge, response) = response
#         self.assertEqual(challenge, expectedChallenge)
#         self.assertEqual(response, expectedResponse)
# 
#     def test_checkSolution(self):
#         """checkSolution() should return False is the solution is invalid."""
#         expectedChallenge = '23232323232323232323'
#         expectedResponse = 'awefawefaefawefaewf'
# 
#         self.request.method = b'POST'
#         self.request.addArg('captcha_challenge_field', expectedChallenge)
#         self.request.addArg('captcha_response_field', expectedResponse)
# 
#         valid = self.captchaResource.checkSolution(self.request)
#         self.assertFalse(valid)
# 
#     def test_getCaptchaImage(self):
#         """Retrieving a (captcha, challenge) pair with an empty captchaDir
#         should return None for both of the (captcha, challenge) strings.
#         """
#         self.request.method = b'GET'
#         response = self.captchaResource.getCaptchaImage(self.request)
#         (image, challenge) = response
#         # Because we created the directory, there weren't any CAPTCHAs to
#         # retrieve from it:
#         self.assertIs(image, None)
#         self.assertIs(challenge, None)
# 
#     def test_getCaptchaImage_noCaptchaDir(self):
#         """Retrieving a (captcha, challenge) with an missing captchaDir should
#         raise a bridgedb.captcha.GimpCaptchaError.
#         """
#         shutil.rmtree(self.captchaDir)
#         self.request.method = b'GET'
#         self.assertRaises(server.captcha.GimpCaptchaError,
#                           self.captchaResource.getCaptchaImage, self.request)
# 
#     def test_render_GET_missingTemplate(self):
#         """render_GET() with a missing template should raise an error and
#         return the result of replaceErrorPage().
#         """
#         oldLookup = server.lookup
#         try:
#             server.lookup = None
#             self.request.method = b'GET'
#             page = self.captchaResource.render_GET(self.request)
#             errorPage = server.replaceErrorPage(self.request, Exception('kablam'))
#             self.assertEqual(page, errorPage)
#         finally:
#             server.lookup = oldLookup
# 
#     def test_render_POST_blankFields(self):
#         """render_POST() with a blank 'captcha_response_field' should return
#         a redirect to the CaptchaProtectedResource page.
#         """
#         self.request.method = b'POST'
#         self.request.addArg('captcha_challenge_field', '')
#         self.request.addArg('captcha_response_field', '')
# 
#         page = self.captchaResource.render_POST(self.request)
#         self.assertEqual(BeautifulSoup(page).find('meta')['http-equiv'],
#                          'refresh')
# 
#     def test_render_POST_wrongSolution(self):
#         """render_POST() with a wrong 'captcha_response_field' should return
#         a redirect to the CaptchaProtectedResource page.
#         """
#         expectedChallenge = '23232323232323232323'
#         expectedResponse = 'awefawefaefawefaewf'
# 
#         self.request.method = b'POST'
#         self.request.addArg('captcha_challenge_field', expectedChallenge)
#         self.request.addArg('captcha_response_field', expectedResponse)
# 
#         page = self.captchaResource.render_POST(self.request)
#         self.assertEqual(BeautifulSoup(page).find('meta')['http-equiv'],
#                          'refresh')
# 
# 
# class BridgesResourceTests(unittest.TestCase):
#     """Tests for :class:`https.server.BridgesResource`."""
# 
#     def setUp(self):
#         """Set up our resources to fake a minimal HTTP(S) server."""
#         self.pagename = b'bridges.html'
#         self.root = Resource()
# 
#         self.dist = DummyHTTPSDistributor()
#         self.sched = ScheduledInterval(1, 'hour')
#         self.nBridgesPerRequest = 2
# 
#     def useBenignBridges(self):
#         self.dist._bridge_class = DummyBridge
#         self.bridgesResource = server.BridgesResource(
#             self.dist, self.sched, N=self.nBridgesPerRequest,
#             includeFingerprints=True)
#         self.root.putChild(self.pagename, self.bridgesResource)
# 
#     def useMaliciousBridges(self):
#         self.dist._bridge_class = DummyMaliciousBridge
#         self.bridgesResource = server.BridgesResource(
#             self.dist, self.sched, N=self.nBridgesPerRequest,
#             includeFingerprints=True)
#         self.root.putChild(self.pagename, self.bridgesResource)
# 
#     def parseBridgesFromHTMLPage(self, page):
#         """Utility to pull the bridge lines out of an HTML response page.
# 
#         :param str page: A rendered HTML page, as a string.
#         :raises: Any error which might occur.
#         :rtype: list
#         :returns: A list of the bridge lines contained on the **page**.
#         """
#         # The bridge lines are contained in a <div class='bridges'> tag:
#         soup = BeautifulSoup(page)
#         well = soup.find('div', {'class': 'bridge-lines'})
#         content = well.renderContents().strip()
#         lines = content.splitlines()
# 
#         bridges = []
#         for line in lines:
#             bridgelines = line.split('<br />')
#             for bridge in bridgelines:
#                 if bridge:  # It still could be an empty string at this point
#                     bridges.append(bridge)
# 
#         return bridges
# 
#     def test_render_GET_malicious_newlines(self):
#         """Test rendering a request when the some of the bridges returned have
#         malicious (HTML, Javascript, etc., in their) PT arguments.
#         """
#         self.useMaliciousBridges()
# 
#         request = DummyRequest([self.pagename])
#         request.method = b'GET'
#         request.getClientIP = lambda: '1.1.1.1'
# 
#         page = self.bridgesResource.render(request)
#         self.assertTrue(
#             'bad=Bridge 6.6.6.6:6666 0123456789abcdef0123456789abcdef01234567' in str(page),
#             "Newlines in bridge lines should be removed.")
# 
#     def test_render_GET_malicious_returnchar(self):
#         """Test rendering a request when the some of the bridges returned have
#         malicious (HTML, Javascript, etc., in their) PT arguments.
#         """
#         self.useMaliciousBridges()
# 
#         request = DummyRequest([self.pagename])
#         request.method = b'GET'
#         request.getClientIP = lambda: '1.1.1.1'
# 
#         page = self.bridgesResource.render(request)
#         self.assertTrue(
#             'eww=Bridge 1.2.3.4:1234' in str(page),
#             "Return characters in bridge lines should be removed.")
# 
#     def test_render_GET_malicious_javascript(self):
#         """Test rendering a request when the some of the bridges returned have
#         malicious (HTML, Javascript, etc., in their) PT arguments.
#         """
#         self.useMaliciousBridges()
# 
#         request = DummyRequest([self.pagename])
#         request.method = b'GET'
#         request.getClientIP = lambda: '1.1.1.1'
# 
#         page = self.bridgesResource.render(request)
#         self.assertTrue(
#             "evil=&lt;script&gt;alert(&#39;fuuuu&#39;);&lt;/script&gt;" in str(page),
#             ("The characters &, <, >, ', and \" in bridge lines should be "
#              "replaced with their corresponding HTML special characters."))
# 
#     def test_renderAnswer_GET_textplain_malicious(self):
#         """If the request format specifies 'plain', we should return content
#         with mimetype 'text/plain' and ASCII control characters replaced.
#         """
#         self.useMaliciousBridges()
# 
#         request = DummyRequest([self.pagename])
#         request.args.update({'format': ['plain']})
#         request.getClientIP = lambda: '4.4.4.4'
#         request.method = b'GET'
# 
#         page = self.bridgesResource.render(request)
#         self.assertTrue("html" not in str(page))
#         self.assertTrue(
#             'eww=Bridge 1.2.3.4:1234' in str(page),
#             "Return characters in bridge lines should be removed.")
#         self.assertTrue(
#             'bad=Bridge 6.6.6.6:6666' in str(page),
#             "Newlines in bridge lines should be removed.")
# 
#     def test_render_GET_vanilla(self):
#         """Test rendering a request for normal, vanilla bridges."""
#         self.useBenignBridges()
# 
#         request = DummyRequest([self.pagename])
#         request.method = b'GET'
#         request.getClientIP = lambda: '1.1.1.1'
# 
#         page = self.bridgesResource.render(request)
# 
#         # The response should explain how to use the bridge lines:
#         self.assertTrue("To enter bridges into Tor Browser" in str(page))
# 
#         for b in self.parseBridgesFromHTMLPage(page):
#             # Check that each bridge line had the expected number of fields:
#             fields = b.split(' ')
#             self.assertEqual(len(fields), 2)
# 
#             # Check that the IP and port seem okay:
#             ip, port = fields[0].rsplit(':')
#             self.assertIsInstance(ipaddr.IPv4Address(ip), ipaddr.IPv4Address)
#             self.assertIsInstance(int(port), int)
#             self.assertGreater(int(port), 0)
#             self.assertLessEqual(int(port), 65535)
# 
#     def test_render_GET_XForwardedFor(self):
#         """The client's IP address should be obtainable from the
#         'X-Forwarded-For' header in the request.
#         """
#         self.useBenignBridges()
# 
#         self.bridgesResource.useForwardedHeader = True
#         request = DummyRequest([self.pagename])
#         request.method = b'GET'
#         # Since we do not set ``request.getClientIP`` here like we do in some
#         # of the other unittests, an exception would be raised here if
#         # ``getBridgesForRequest()`` is unable to get the IP address from this
#         # 'X-Forwarded-For' header (because ``ip`` would get set to ``None``).
#         request.headers.update({'x-forwarded-for': '2.2.2.2'})
# 
#         page = self.bridgesResource.render(request)
#         self.bridgesResource.useForwardedHeader = False  # Reset it
# 
#         # The response should explain how to use the bridge lines:
#         self.assertTrue("To enter bridges into Tor Browser" in str(page))
# 
#     def test_render_GET_RTLlang(self):
#         """Test rendering a request for plain bridges in Arabic."""
#         self.useBenignBridges()
# 
#         request = DummyRequest([b"bridges?transport=obfs3"])
#         request.method = b'GET'
#         request.getClientIP = lambda: '3.3.3.3'
#         # For some strange reason, the 'Accept-Language' value *should not* be
#         # a list, unlike all the other headers and args…
#         request.headers.update({'accept-language': 'ar,en,en_US,'})
# 
#         page = self.bridgesResource.render(request)
#         self.assertSubstring("rtl.css", page)
#         self.assertSubstring(
#             # "I need an alternative way to get bridges!"
#             "أحتاج إلى وسيلة بديلة للحصول على bridges", page)
# 
#         for bridgeLine in self.parseBridgesFromHTMLPage(page):
#             # Check that each bridge line had the expected number of fields:
#             bridgeLine = bridgeLine.split(' ')
#             self.assertEqual(len(bridgeLine), 2)
# 
#     def test_render_GET_RTLlang_obfs3(self):
#         """Test rendering a request for obfs3 bridges in Farsi."""
#         self.useBenignBridges()
# 
#         request = DummyRequest([b"bridges?transport=obfs3"])
#         request.method = b'GET'
#         request.getClientIP = lambda: '3.3.3.3'
#         request.headers.update({'accept-language': 'fa,en,en_US,'})
#         # We actually have to set the request args manually when using a
#         # DummyRequest:
#         request.args.update({'transport': ['obfs3']})
# 
#         page = self.bridgesResource.render(request)
#         self.assertSubstring("rtl.css", page)
#         self.assertSubstring(
#             # "How to use the above bridge lines" (since there should be
#             # bridges in this response, we don't tell them about alternative
#             # mechanisms for getting bridges)
#             "چگونگی از پل‌های خود استفاده کنید", page)
# 
#         for bridgeLine in self.parseBridgesFromHTMLPage(page):
#             # Check that each bridge line had the expected number of fields:
#             bridgeLine = bridgeLine.split(' ')
#             self.assertEqual(len(bridgeLine), 3)
#             self.assertEqual(bridgeLine[0], 'obfs3')
# 
#             # Check that the IP and port seem okay:
#             ip, port = bridgeLine[1].rsplit(':')
#             self.assertIsInstance(ipaddr.IPv4Address(ip), ipaddr.IPv4Address)
#             self.assertIsInstance(int(port), int)
#             self.assertGreater(int(port), 0)
#             self.assertLessEqual(int(port), 65535)
# 
#     def test_renderAnswer_textplain(self):
#         """If the request format specifies 'plain', we should return content
#         with mimetype 'text/plain'.
#         """
#         self.useBenignBridges()
# 
#         request = DummyRequest([self.pagename])
#         request.args.update({'format': ['plain']})
#         request.getClientIP = lambda: '4.4.4.4'
#         request.method = b'GET'
# 
#         page = self.bridgesResource.render(request)
#         self.assertTrue("html" not in str(page))
# 
#         # We just need to strip and split it because it looks like:
#         #
#         #   94.235.85.233:9492 0d9d0547c3471cddc473f7288a6abfb54562dc06
#         #   255.225.204.145:9511 1fb89d618b3a12afe3529fd072127ea08fb50466
#         #
#         # (Yes, there are two leading spaces at the beginning of each line)
#         #
#         bridgeLines = [line.strip() for line in page.strip().split('\n')]
# 
#         for bridgeLine in bridgeLines:
#             bridgeLine = bridgeLine.split(' ')
#             self.assertEqual(len(bridgeLine), 2)
# 
#             # Check that the IP and port seem okay:
#             ip, port = bridgeLine[0].rsplit(':')
#             self.assertIsInstance(ipaddr.IPv4Address(ip), ipaddr.IPv4Address)
#             self.assertIsInstance(int(port), int)
#             self.assertGreater(int(port), 0)
#             self.assertLessEqual(int(port), 65535)
# 
#     def test_renderAnswer_textplain_error(self):
#         """If we hit some error while returning bridge lines in text/plain
#         format, then our custom plaintext error message (the hardcoded HTML in
#         ``server.replaceErrorPage``) should be returned.
#         """
#         self.useBenignBridges()
# 
#         request = DummyRequest([self.pagename])
#         request.args.update({'format': ['plain']})
#         request.getClientIP = lambda: '4.4.4.4'
#         request.method = b'GET'
# 
#         # We'll cause a TypeError here due to calling '\n'.join(None)
#         page = self.bridgesResource.renderAnswer(request, bridgeLines=None)
# 
#         # We don't want the fancy version:
#         self.assertNotSubstring("Bad News Bears", page)
#         self.assertSubstring("Sorry! Something went wrong with your request.",
#                              page)
# 
# 
# class HTTPSServerServiceTests(unittest.TestCase):
#     """Unittests for :func:`bridgedb.email.server.addWebServer`."""
# 
#     def setUp(self):
#         """Create a config and an HTTPSDistributor."""
#         self.config = _createConfig()
#         self.distributor = DummyHTTPSDistributor()
# 
#     def tearDown(self):
#         """Cleanup method after each ``test_*`` method runs; removes timed out
#         connections on the reactor and clears the :ivar:`transport`.
# 
#         Basically, kill all connections with fire.
#         """
#         for delay in reactor.getDelayedCalls():
#             try:
#                 delay.cancel()
#             except (AlreadyCalled, AlreadyCancelled):
#                 pass
# 
#         # FIXME: this is definitely not how we're supposed to do this, but it
#         # kills the DirtyReactorAggregateErrors.
#         reactor.disconnectAll()
#         reactor.runUntilCurrent()
# 
#     def test_addWebServer_GIMP_CAPTCHA_ENABLED(self):
#         """Call :func:`bridgedb.https.server.addWebServer` to test startup."""
#         server.addWebServer(self.config, self.distributor)
# 
#     def test_addWebServer_RECAPTCHA_ENABLED(self):
#         """Call :func:`bridgedb.https.server.addWebServer` to test startup."""
#         config = self.config
#         config.RECAPTCHA_ENABLED = True
#         server.addWebServer(config, self.distributor)
# 
#     def test_addWebServer_no_captchas(self):
#         """Call :func:`bridgedb.https.server.addWebServer` to test startup."""
#         config = self.config
#         config.GIMP_CAPTCHA_ENABLED = False
#         server.addWebServer(config, self.distributor)
# 
#     def test_addWebServer_no_HTTPS_ROTATION_PERIOD(self):
#         """Call :func:`bridgedb.https.server.addWebServer` to test startup."""
#         config = self.config
#         config.HTTPS_ROTATION_PERIOD = None
#         server.addWebServer(config, self.distributor)
# 
#     def test_addWebServer_CSP_ENABLED_False(self):
#         """Call :func:`bridgedb.https.server.addWebServer` with
#         ``CSP_ENABLED=False`` to test startup.
#         """
#         config = self.config
#         config.CSP_ENABLED = False
#         server.addWebServer(config, self.distributor)
# 
#     def test_addWebServer_CSP_REPORT_ONLY_False(self):
#         """Call :func:`bridgedb.https.server.addWebServer` with
#         ``CSP_REPORT_ONLY=False`` to test startup.
#         """
#         config = self.config
#         config.CSP_REPORT_ONLY = False
#         server.addWebServer(config, self.distributor)
# 
#     def test_addWebServer_CSP_INCLUDE_SELF_False(self):
#         """Call :func:`bridgedb.https.server.addWebServer` with
#         ``CSP_INCLUDE_SELF=False`` to test startup.
#         """
#         config = self.config
#         config.CSP_INCLUDE_SELF = False
#         server.addWebServer(config, self.distributor)
