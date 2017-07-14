# -*- coding: utf-8 ; test-case-name: farfetchd.test.test_schedule -*-
#
# This file is part of farfetchd, a server for CAPTCHA challenge creation and
# response verification.
#
# :authors: Isis Lovecruft 0xA3ADB67A2CDB8B35 <isis@torproject.org>
# :copyright: (c) 2013-2017, Isis Lovecruft
#             (c) 2007-2017, The Tor Project, Inc.
# :license: see LICENSE for licensing information

"""This module implements functions for dividing time into chunks.

.. inheritance-diagram:: UnknownInterval Unscheduled ScheduledInterval
    :parts: 1
"""

import calendar

import math

from datetime import datetime

from zope import interface
from zope.interface import implementer
from zope.interface import Attribute


#: The known time intervals (or *periods*) for dividing time by.
KNOWN_INTERVALS = ["second", "minute", "hour", "day", "week", "month"]


class UnknownInterval(ValueError):
    """Raised if an interval isn't one of the :data:`KNOWN_INTERVALS`."""


def toUnixSeconds(timestruct):
    """Convert a datetime struct to a Unix timestamp in seconds.

    :type timestruct: :any:`datetime.datetime`
    :param timestruct: A ``datetime`` object to convert into a timestamp in
        Unix Era seconds.
    :rtype: int
    """
    return calendar.timegm(timestruct)

def fromUnixSeconds(timestamp):
    """Convert a Unix timestamp to a datetime struct.

    :param int timestamp: A timestamp in Unix Era seconds.
    :rtype: :any:`datetime.datetime`
    """
    return datetime.fromtimestamp(timestamp)


class ISchedule(interface.Interface):
    """An ``Interface`` specification for a Schedule."""

    intervalPeriod = Attribute(
        "The type of period which this Schedule's intervals will rotate by.")
    intervalCount = Attribute(
        "Number of **intervalPeriod**s before rotation to the next interval")

    def intervalStart(when=None):
        """Get the start time of the interval that contains **when**."""

    def getInterval(when=None):
        """Get the interval which includes an arbitrary **when**."""

    def nextIntervalStarts(when=None):
        """Get the start of the interval after the one containing **when**."""


@implementer(ISchedule)
class Unscheduled(object):
    """A base ``Schedule`` that has only one period that contains all time.

    >>> from farfetchd.schedule import fromUnixSeconds
    >>> from farfetchd.schedule import Unscheduled
    >>> timestamp = 1427769526
    >>> str(fromUnixSeconds(timestamp))
    '2015-03-31 02:38:46'
    >>> sched = Unscheduled()
    >>> start = sched.intervalStart(timestamp)
    >>> start
    -62135596800
    >>> str(fromUnixSeconds(start))
    '0001-01-01 00:00:00'
    >>> sched.getInterval(timestamp)
    '1970-01-01 00:00:00'
    >>> next = sched.nextIntervalStarts(timestamp)
    >>> next
    253402300799
    >>> str(fromUnixSeconds(next))
    '9999-12-31 23:59:59'

    """

    def __init__(self, count=None, period=None):
        """Create a schedule for dividing time into intervals.

        :param int count: The total number of **period** in one interval.
        :param str period: One of the periods in :data:`KNOWN_INTERVALS`.
        """
        self.intervalCount = count
        self.intervalPeriod = period

    def intervalStart(self, when=0):
        """Get the start time of the interval that contains **when**.

        :param int when: The time which we're trying to find the corresponding
            interval for.
        :rtype: int
        :returns: The Unix epoch timestamp for the start time of the interval
            that contains **when**.
        """
        return toUnixSeconds(datetime.min.timetuple())

    def getInterval(self, when=0):
        """Get the interval that contains the time **when**.

        .. note: We explicitly ignore the ``when`` parameter in this
            implementation because if something is Unscheduled then
            all timestamps should reside within the same period.

        :param int when: The time which we're trying to find the corresponding
            interval for.
        :rtype: str
        :returns: A timestamp in the form ``YEAR-MONTH[-DAY[-HOUR]]``. It's
            specificity depends on what type of interval we're using. For
            example, if using ``"month"``, the return value would be something
            like ``"2013-12"``.
        """
        return fromUnixSeconds(0).strftime('%04Y-%02m-%02d %02H:%02M:%02S')

    def nextIntervalStarts(self, when=0):
        """Return the start time of the interval starting _after_ when.

        :rtype: int
        :returns: Return the Y10K bug.
        """
        return toUnixSeconds(datetime.max.timetuple())


@implementer(ISchedule)
class ScheduledInterval(Unscheduled):
    """An class that splits time into periods, based on seconds, minutes,
    hours, days, weeks, or months.

    >>> from farfetchd.schedule import fromUnixSeconds
    >>> from farfetchd.schedule import ScheduledInterval
    >>> timestamp = 1427769526
    >>> str(fromUnixSeconds(timestamp))
    '2015-03-31 02:38:46'
    >>> sched = ScheduledInterval(5, 'minutes')
    >>> start = sched.intervalStart(timestamp)
    >>> start
    1427769300
    >>> current = sched.getInterval(timestamp)
    >>> current
    '2015-03-31 02:35:00'
    >>> current == str(fromUnixSeconds(start))
    True
    >>> next = sched.nextIntervalStarts(timestamp)
    >>> next
    1427769600
    >>> str(fromUnixSeconds(next))
    '2015-03-31 02:40:00'
    >>> later = 1427771057
    >>> str(fromUnixSeconds(later))
    '2015-03-31 03:04:17'
    >>> sched.getInterval(later)
    '2015-03-31 03:00:00'

    :ivar str intervalPeriod: One of the :data:`KNOWN_INTERVALS`.
    :ivar int intervalCount: The number of times :attr:`intervalPeriod` should
        be repeated within an interval.
    """

    def __init__(self, count=None, period=None):
        """Create a schedule for dividing time into intervals.

        :type count: :any:`int` or :any:`str`
        :param count: The total number of **period** in one interval.
        :param str period: One of the periods in :data:`KNOWN_INTERVALS`.
        """
        super(ScheduledInterval, self).__init__(count, period)
        self._setIntervalCount(count)
        self._setIntervalPeriod(period)

    def _setIntervalCount(self, count=None):
        """Set our :attr:`intervalCount`.

        .. attention:: This method should be called *before*
            :meth:`_setIntervalPeriod`, because the latter may change the
            count, if it decides to change the period (for example, to
            simplify things by changing weeks into days).

        :param int count: The number of times the :attr:`intervalPeriod`
            should be repeated during the interval. Defaults to ``1``.
        :raises UnknownInterval: if the specified **count** was invalid.
        """
        try:
            if not count > 0:
                count = 1
            count = int(count)
        except (TypeError, ValueError):
            raise UnknownInterval("%s.intervalCount: %r ist not an integer."
                                  % (self.__class__.__name__, count))
        self.intervalCount = count

    def _setIntervalPeriod(self, period=None):
        """Set our :attr:`intervalPeriod`.

        :param str period: One of the :data:`KNOWN_INTERVALS`, or its
            plural. Defaults to ``'hour'``.
        :raises UnknownInterval: if the specified **period** is unknown.
        """
        if not period:
            period = 'hour'
        try:
            period = period.lower()
            # Depluralise the period if necessary, i.e., "months" -> "month".
            if period.endswith('s'):
                period = period[:-1]

            if not period in KNOWN_INTERVALS:
                raise ValueError
        except (TypeError, AttributeError, ValueError):
            raise UnknownInterval("%s doesn't know about the %r interval type."
                                  % (self.__class__.__name__, period))
        self.intervalPeriod = period

        if period == 'week':
            self.intervalPeriod = 'day'
            self.intervalCount *= 7

    def intervalStart(self, when=0):
        """Get the start time of the interval that contains **when**.

        :param int when: The time which we're trying to determine the start of
            interval that contains it. This should be given in Unix seconds,
            for example, taken from :func:`calendar.timegm`.
        :rtype: int
        :returns: The Unix epoch timestamp for the start time of the interval
            that contains **when**.
        """
        # Convert `when`s which are floats, i.e. from time.time(), to ints:
        when = int(math.ceil(when))

        if self.intervalPeriod == 'month':
            # For months, we always start at the beginning of the month.
            date = fromUnixSeconds(when)
            months = (date.year * 12) + (date.month - 1)
            months -= (months % self.intervalCount)
            month = months % 12 + 1
            return toUnixSeconds((months // 12, month, 1, 0, 0, 0))
        elif self.intervalPeriod == 'day':
            # For days, we start at the beginning of a day.
            when -= when % (86400 * self.intervalCount)
            return when
        elif self.intervalPeriod == 'hour':
            # For hours, we start at the beginning of an hour.
            when -= when % (3600 * self.intervalCount)
            return when
        elif self.intervalPeriod == 'minute':
            when -= when % (60 * self.intervalCount)
            return when
        elif self.intervalPeriod == 'second':
            when -= when % self.intervalCount
            return when

    def getInterval(self, when=0):
        """Get the interval that contains the time **when**.

        >>> import calendar
        >>> from farfetchd.schedule import ScheduledInterval
        >>> sched = ScheduledInterval(1, 'month')
        >>> when = calendar.timegm((2007, 12, 12, 0, 0, 0))
        >>> sched.getInterval(when)
        '2007-12'
        >>> then = calendar.timegm((2014, 05, 13, 20, 25, 13))
        >>> sched.getInterval(then)
        '2014-05'

        :param int when: The time which we're trying to find the corresponding
            interval for. Given in Unix seconds, for example, taken from
            :func:`calendar.timegm`.
        :rtype: str
        :returns: A timestamp in the form ``YEAR-MONTH[-DAY[-HOUR]]``. It's
            specificity depends on what type of interval we're using. For
            example, if using ``"month"``, the return value would be something
            like ``"2013-12"``.
        """
        date = fromUnixSeconds(self.intervalStart(when))

        fstr = "%04Y-%02m"
        if self.intervalPeriod != 'month':
            fstr += "-%02d"
            if self.intervalPeriod != 'day':
                fstr += " %02H"
                if self.intervalPeriod != 'hour':
                    fstr += ":%02M"
                    if self.intervalPeriod == 'minute':
                        fstr += ":%02S"

        return date.strftime(fstr)

    def nextIntervalStarts(self, when=0):
        """Return the start time of the interval starting _after_ when.

        :returns: The Unix epoch timestamp for the start time of the interval
            that contains **when**.
        """
        seconds = self.intervalStart(when)

        if self.intervalPeriod == 'month':
            date = fromUnixSeconds(seconds)
            year = date.year
            months = date.month + self.intervalCount
            if months > 12:
                year = date.year + 1
                months = months - 12
            return toUnixSeconds((year, months, 1, 0, 0, 0))
        elif self.intervalPeriod == 'day':
            return seconds + (86400 * self.intervalCount)
        elif self.intervalPeriod == 'hour':
            return seconds + (3600 * self.intervalCount)
        elif self.intervalPeriod == 'minute':
            return seconds + (60 * self.intervalCount)
        elif self.intervalPeriod == 'second':
            return seconds + self.intervalCount
