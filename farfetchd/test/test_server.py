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

import json
import logging
import os
import shutil

from twisted.internet import reactor
from twisted.internet import task
from twisted.trial import unittest
from twisted.web.resource import Resource
from twisted.web.test import requesthelper

from farfetchd import server
from farfetchd import crypto

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
        self.assertSubstring("farfetchd API Specification", page)


class CaptchaFetchResourceTests(unittest.TestCase):
    """Tests for :mod:`farfetchd.server.CaptchaFetchResource`."""

    def setUp(self):
        """Create a :class:`CaptchaFetchResource`.
        """
        secretKey, publicKey = crypto.getRSAKey('captcha.key', bits=1024)

        # Set up our resources to fake a minimal HTTP(S) server:
        self.pagename = b'fetch'
        self.root = Resource()

        shutil.copytree('../captchas', os.path.sep.join([os.getcwd(), 'captchas']))

        self.captchaDir = os.path.sep.join([os.getcwd(), 'captchas'])
        self.captchaResource = server.CaptchaFetchResource(
            secretKey=secretKey,
            publicKey=publicKey,
            hmacKey='abcdefghijklmnopqrstuvwxyz012345',
            captchaDir=self.captchaDir,
            useForwardedHeader=True)

        self.root.putChild(self.pagename, self.captchaResource)

        # Set up the basic parts of our faked request:
        self.request = DummyRequest([self.pagename])

    def test_getCaptchaImage_empty(self):
        """Retrieving a (captcha, challenge) pair with an empty captchaDir
        should return (None, None).
        """
        shutil.move(self.captchaDir, self.captchaDir + ".orig")
        os.mkdir(self.captchaDir)

        self.request.method = b'GET'
        captcha, challenge = self.captchaResource.getCaptchaImage(self.request)
        self.assertIsNone(captcha)
        self.assertIsNone(challenge)

    def test_getCaptchaImage_noCaptchaDir(self):
        """Retrieving a (captcha, challenge) with an missing captchaDir should
        raise a farfetchd.captcha.GimpCaptchaError.
        """
        shutil.move(self.captchaDir, self.captchaDir + ".orig")

        self.request.method = b'GET'
        self.assertRaises(server.captcha.GimpCaptchaError,
                          self.captchaResource.getCaptchaImage, self.request)

    def test_get(self):
        """Test making a GET request to /fetch."""
        self.request.method = b'GET'

        response = self.captchaResource.render(self.request)

        self.assertIn('data', response)
        self.assertIn('id', response)
        self.assertIn('type', response)
        self.assertIn('version', response)
        self.assertIn('image',   response)
        self.assertIn('challenge', response)

    def tearDown(self):
        captchaDir = os.path.sep.join([os.getcwd(), 'captchas'])

        if os.path.exists(captchaDir):
            shutil.rmtree(captchaDir)


class CaptchaCheckResourceTests(unittest.TestCase):
    """Tests for :mod:`farfetchd.server.CaptchaCheckResource`."""

    def setUp(self):
        """Create a :class:`CaptchaFetchResource`.
        """
        secretKey, publicKey = crypto.getRSAKey('captcha.key', bits=1024)

        # Set up our resources to fake a minimal HTTP(S) server:
        self.pagename = b'check'
        self.root = Resource()

        shutil.copytree('../captchas', os.path.sep.join([os.getcwd(), 'captchas']))

        self.captchaDir = os.path.sep.join([os.getcwd(), 'captchas'])
        self.captchaResource = server.CaptchaCheckResource(
            secretKey=secretKey,
            publicKey=publicKey,
            hmacKey='abcdefghijklmnopqrstuvwxyz012345',
            useForwardedHeader=True)

        self.root.putChild(self.pagename, self.captchaResource)

        # Set up the basic parts of our faked request:
        self.request = DummyRequest([self.pagename])

    def tearDown(self):
        captchaDir = os.path.sep.join([os.getcwd(), 'captchas'])

        if os.path.exists(captchaDir):
            shutil.rmtree(captchaDir)

    def test_extractClientSolution_matches(self):
        """A (challenge, sollution) pair extracted from a request resulting
        from a POST should have the same unmodified (challenge, sollution) as
        the client originally POSTed.
        """
        expectedChallenge = '23232323232323232323'
        expectedResponse = 'awefawefaefawefaewf'

        data = {
            'data': {
                'id': 2,
                'type': 'check',
                'version': server.FARFETCHD_API_VERSION,
                'challenge': expectedChallenge,
                'solution': expectedResponse,
            }
        }

        self.request.method = b'POST'
        self.request.writeContent(json.dumps(data))

        response = self.captchaResource.extractClientSolution(self.request)
        (challenge, response) = response
        self.assertEqual(challenge, expectedChallenge)
        self.assertEqual(response, expectedResponse)

    def test_extractClientSolution_not_json(self):
        """If the POST contains non json, the (challenge solution) pair should
        be (None, None).
        """
        data = {
            'data': {
                'id': 2,
                'type': 'check',
                'version': server.FARFETCHD_API_VERSION,
                'challenge': '23232323232323232323',
                'solution': 'awefawefaefawefaewf',
            }
        }
        self.request.method = b'POST'
        self.request.writeContent("<html><body>" + json.dumps(data) + "</body></html>")

        response = self.captchaResource.extractClientSolution(self.request)
        (challenge, response) = response
        self.assertIsNone(challenge)
        self.assertIsNone(response)

    def test_extractClientSolution_bad_type(self):
        """If the POST a bad "type" field, the (challenge solution) pair should
        be (None, None).
        """
        data = {
            'data': {
                'id': 2,
                'type': 'bad',
                'version': server.FARFETCHD_API_VERSION,
                'challenge': '23232323232323232323',
                'solution': 'awefawefaefawefaewf',
            }
        }
        self.request.method = b'POST'
        self.request.writeContent(json.dumps(data))

        response = self.captchaResource.extractClientSolution(self.request)
        (challenge, response) = response
        self.assertIsNone(challenge)
        self.assertIsNone(response)

    def test_extractClientSolution_bad_version(self):
        """If the POST an unrecognised "version" field, the (challenge solution)
        pair should be (None, None).
        """
        data = {
            'data': {
                'id': 2,
                'type': 'check',
                'version': 'a.b.c',
                'challenge': '23232323232323232323',
                'solution': 'awefawefaefawefaewf',
            }
        }
        self.request.method = b'POST'
        self.request.writeContent(json.dumps(data))

        response = self.captchaResource.extractClientSolution(self.request)
        (challenge, response) = response
        self.assertIsNone(challenge)
        self.assertIsNone(response)

    def test_extractClientSolution_bad_id(self):
        """If the POST an unrecognised "id" field, the (challenge solution)
        pair should be (None, None).
        """
        data = {
            'data': {
                'id': 23,
                'type': 'check',
                'version': server.FARFETCHD_API_VERSION,
                'challenge': '23232323232323232323',
                'solution': 'awefawefaefawefaewf',
            }
        }
        self.request.method = b'POST'
        self.request.writeContent(json.dumps(data))

        response = self.captchaResource.extractClientSolution(self.request)
        (challenge, response) = response
        self.assertIsNone(challenge)
        self.assertIsNone(response)

    def test_checkSolution(self):
        """checkSolution() should return False is the solution is invalid."""
        expectedChallenge = '23232323232323232323'
        expectedResponse = 'awefawefaefawefaewf'

        data = {
            'data': {
                'id': 2,
                'type': 'check',
                'version': server.FARFETCHD_API_VERSION,
                'challenge': expectedChallenge,
                'solution': expectedResponse,
            }
        }

        self.request.method = b'POST'
        self.request.writeContent(json.dumps(data))

        valid = self.captchaResource.checkSolution(self.request)
        self.assertFalse(valid)

    def test_render_POST_blankFields(self):
        """render_POST() with a blank 'captcha_response_field' should return
        a redirect to the CaptchaProtectedResource page.
        """
        data = {
            'data': {
                'id': 2,
                'type': 'check',
                'version': server.FARFETCHD_API_VERSION,
                'challenge': '',
                'solution': '',
            }
        }

        self.request.method = b'POST'
        self.request.writeContent(json.dumps(data))

        response = self.captchaResource.render_POST(self.request)

        # XXX need a way to check that the response code is 419
        self.assertEqual("", response)

    def test_render_POST_wrong_solution(self):
        """render_POST() with a wrong solution should return a failure response.
        """
        data = {
            'data': {
                'id': 2,
                'type': 'check',
                'version': server.FARFETCHD_API_VERSION,
                'challenge': 'aaewpfaoiweja',
                'solution': 'Tvx74PMy',
            }
        }

        self.request.method = b'POST'
        self.request.writeContent(json.dumps(data))

        response = self.captchaResource.render_POST(self.request)

        # XXX need a way to check that the response code is 419
        self.assertEqual("", response)


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
