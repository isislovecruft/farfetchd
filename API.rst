=============================
 farfetchd API Specification
=============================

The following specification describes farfetchd API version 0.1.0.

The client and server both MUST conform to `JSON-API <http://jsonapi.org/>`_.

Requesting a CAPTCHA
--------------------

Request
~~~~~~~

To obtain a CAPTCHA, the client MUST send a request for ``GET /fetch``.

Response
~~~~~~~~

The farfetchd server SHOULD respond ``200 OK`` and include JSON in the following format::

    {
      'data': {
        'id': 1,
        'type': "fetch",
        'version': FARFETCHD_API_VERSION,
        'image': CAPTCHA,
        'challenge': CHALLENGE,
      }
    }


where:

* ``FARFETCHED_API_VERSION`` is the current API version (currently "0.1.0"),
* ``CAPTCHA`` is a base64-encoded, jpeg image that is 400 pixels in
  length and 125 pixels in height,
* ``CHALLENGE`` is a base64-encoded CAPTCHA challenge which MUST be
  later passed back to the server along with the proposed solution.

The challenge contains an encrypted-then-HMACed timestamp, and
solutions submitted more than 30 minutes after requesting the CAPTCHA
are considered invalid.


Checking the solution to a CAPTCHA
----------------------------------

Request
~~~~~~~

To propose a solution to a CAPTCHA, the client MUST send a request for
``POST /check``, where the body of the request contains the following JSON::

    {
      'data': {
        'id': 2,
        'type': "check",
        'version': FARFETCHD_API_VERSION,
        'challenge': CHALLENGE,
        'solution': SOLUTION,
      }
    }


where:

* ``FARFETCHED_API_VERSION`` is the current API version (currently "0.1.0"),
* ``CHALLENGE`` is a base64-encoded CAPTCHA challenge which MUST be
  later passed back to the server along with the proposed solution.
* ``SOLUTION`` is a valid unicode string, up to 20 bytes in length,
  containing the client's answer (i.e. what characters the CAPTCHA
  image displayed).  The solution is *not* case-sensitive.

Response
~~~~~~~~

If the ``CHALLENGE`` has already timed out, or if the ``SOLUTION`` was
incorrect, the server SHOULD respond with ``419 No You're A Teapot``.

If the ``SOLUTION`` was successful for the supplied ``CHALLENGE``, the
server responds ``200 OK`` with the following JSON::

    {
      'data': {
        'id': 3,
        'type': "check",
        'version': FARFETCHD_API_VERSION,
        'result': BOOLEAN,
      }
    }

where:

* ``FARFETCHED_API_VERSION`` is the current API version (currently "0.1.0"),
* ``BOOLEAN`` is ``"true"`` if the ``SOLUTION`` was correct.


Other responses
---------------

If the client requested some page other than ``/``, ``/fetch``, or
``/check``, the server MUST respond with ``501 Not Implemented``.

If the client attempts to request ``POST /`` or ``POST /fetch``, the
server MUST respond ``403 FORBIDDEN``.
