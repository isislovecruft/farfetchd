#
# This file is part of farfetchd, a CAPTCHA service.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
#           please also see AUTHORS file
# :copyright: (c) 2007-2013, The Tor Project, Inc.
#             (c) 2007-2013, Isis Agora Lovecruft
# :license: 3-clause BSD, see included LICENSE for information

"""A Twisted Python CAPTCHA service."""

from farfetchd._version import get_versions

__version__ = get_versions()['version']

del get_versions
