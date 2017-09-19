
import logging

import ipaddr


def isIPAddress(ip, compressed=True):
    """Check if an arbitrary string is an IP address, and that it's valid.

    :type ip: basestring or int
    :param ip: The IP address to check.
    :param boolean compressed: If True, return a string representing the
        compressed form of the address. Otherwise, return an
        :class:`ipaddr.IPAddress` instance.
    :rtype: A :class:`ipaddr.IPAddress`, or a string, or False
    :returns: The IP, as a string or a class, if it passed the
        checks. Otherwise, returns False.
    """
    try:
        ip = ipaddr.IPAddress(ip)
    except ValueError:
        return False
    else:
        if isValidIP(ip):
            if compressed:
                return ip.compressed
            else:
                return ip
    return False

def isIPv(version, ip):
    """Check if **ip** is a certain **version** (IPv4 or IPv6).

    .. warning: Do *not* put any calls to the logging module in this function,
        or else an infinite recursion will occur when the call is made, due
        the the log :class:`~logging.Filter`s in :mod:`~bridgedb.safelog`
        using this function to validate matches from the regular expression
        for IP addresses.

    :param integer version: The IPv[4|6] version to check; must be either
        ``4`` or ``6``. Any other value will be silently changed to ``4``.
    :param ip: The IP address to check. May be an any type which
        :class:`ipaddr.IPAddress` will accept.
    :rtype: boolean
    :returns: ``True``, if the address is an IPv4 address.
    """
    try:
        ipaddr.IPAddress(ip, version=version)
    except (ipaddr.AddressValueError, Exception):
        return False
    else:
        return True
    return False

def isIPv4(ip):
    """Check if an address is IPv4.

    .. attention:: This does *not* check validity. See :func:`isValidIP`.

    :type ip: basestring or int
    :param ip: The IP address to check.
    :rtype: boolean
    :returns: True if the address is an IPv4 address.
    """
    return isIPv(4, ip)

def isIPv6(ip):
    """Check if an address is IPv6.

    .. attention:: This does *not* check validity. See :func:`isValidIP`.

    :type ip: basestring or int
    :param ip: The IP address to check.
    :rtype: boolean
    :returns: True if the address is an IPv6 address.
    """
    return isIPv(6, ip)

def isValidIP(ip):
    """Check that an IP (v4 or v6) is valid.

    The IP address, **ip**, must not be any of the following:

      * A :term:`Link-Local Address`,
      * A :term:`Loopback Address` or :term:`Localhost Address`,
      * A :term:`Multicast Address`,
      * An :term:`Unspecified Address` or :term:`Default Route`,
      * Any other :term:`Private Address`, or address within a privately
        allocated space, such as the IANA-reserved
        :term:`Shared Address Space`.

    If it is an IPv6 address, it also must not be:

      * A :term:`Site-Local Address` or an :term:`Unique Local Address`.

    >>> from bridgedb.parse.addr import isValidIP
    >>> isValidIP('1.2.3.4')
    True
    >>> isValidIP('1.2.3.255')
    True
    >>> isValidIP('1.2.3.256')
    False
    >>> isValidIP('1')
    False
    >>> isValidIP('1.2.3')
    False
    >>> isValidIP('xyzzy')
    False

    :type ip: An :class:`ipaddr.IPAddress`, :class:`ipaddr.IPv4Address`,
        :class:`ipaddr.IPv6Address`, or str
    :param ip: An IP address. If it is a string, it will be converted to a
        :class:`ipaddr.IPAddress`.
    :rtype: boolean
    :returns: ``True``, if **ip** passes the checks; False otherwise.
    """
    reasons  = []

    try:
        if isinstance(ip, basestring):
            ip = ipaddr.IPAddress(ip)

        if ip.is_link_local:
            reasons.append('link local')
        if ip.is_loopback:
            reasons.append('loopback')
        if ip.is_multicast:
            reasons.append('multicast')
        if ip.is_private:
            reasons.append('private')
        if ip.is_unspecified:
            reasons.append('unspecified')

        if (ip.version == 6) and ip.is_site_local:
            reasons.append('site local')
        elif (ip.version == 4) and ip.is_reserved:
            reasons.append('reserved')
    except ValueError:
        reasons.append('cannot convert to ip')

    if reasons:
        explain = ', '.join([r for r in reasons])
        logging.debug("IP address %r is invalid! Reason(s): %s"
                      % (ip, explain))
        return False
    return True
