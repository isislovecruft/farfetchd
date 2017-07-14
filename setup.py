#!/usr/bin/env python2
#_____________________________________________________________________________
#
# This file is part of farfetchd, a CAPTCHA service.
#
# :authors: Isis Lovecruft <isis@torproject.org>
# :copyright: (c) 2007-2017, The Tor Project, Inc.
#             (c) 2007-2017, Isis Agora Lovecruft
# :license: see LICENSE for licensing information
#_____________________________________________________________________________

from __future__ import print_function

import os
import setuptools
import sys

import versioneer

def get_cmdclass():
    """Get our cmdclass dictionary for use in setuptool.setup().

    This must be done outside the call to setuptools.setup() because we need
    to add our own classes to the cmdclass dictionary, and then update that
    dictionary with the one returned from versioneer.get_cmdclass().
    """
    cmdclass = {'test': Trial,}
    cmdclass.update(versioneer.get_cmdclass())
    return cmdclass

def get_requirements():
    """Extract the list of requirements from our requirements.txt.

    :rtype: 2-tuple
    :returns: Two lists, the first is a list of requirements in the form of
        pkgname==version. The second is a list of URIs or VCS checkout strings
        which specify the dependency links for obtaining a copy of the
        requirement.
    """
    requirements_file = os.path.join(os.getcwd(), 'requirements.txt')
    requirements = []
    links=[]
    try:
        with open(requirements_file) as reqfile:
            for line in reqfile.readlines():
                line = line.strip()
                if line.startswith('#'):
                    continue
                if line.startswith(('git+', 'hg+', 'svn+')):
                    line = line[line.index('+') + 1:]
                if line.startswith(
                        ('https://', 'git://', 'hg://', 'svn://')):
                    links.append(line)
                else:
                    requirements.append(line)

    except (IOError, OSError) as error:
        print(error)

    return requirements, links


class Trial(setuptools.Command):
    """Twisted Trial setuptools command.

    Based on the setuptools Trial command in Zooko's Tahoe-LAFS, as well as
    https://github.com/simplegeo/setuptools-trial/ (which is also based on the
    Tahoe-LAFS code).

    Pieces of the original implementation of this 'test' command (that is, for
    the original pyunit-based BridgeDB tests which, a long time ago, in a
    galaxy far far away, lived in bridgedb.Tests) were based on setup.py from
    Nick Mathewson's mixminion, which was based on the setup.py from Zooko's
    pyutil package, which was in turn based on
    http://mail.python.org/pipermail/distutils-sig/2002-January/002714.html.

    Crusty, old-ass Python, like hella wut.
    """
    description = "Run Twisted Trial-based tests."
    user_options = [
        ('debug', 'b', ("Run tests in a debugger. If that debugger is pdb, will "
                        "load '.pdbrc' from current directory if it exists.")),
        ('debug-stacktraces', 'B', "Report Deferred creation and callback stack traces"),
        ('debugger=', None, ("The fully qualified name of a debugger to use if "
                             "--debug is passed (default: pdb)")),
        ('disablegc', None, "Disable the garbage collector"),
        ('force-gc', None, "Have Trial run gc.collect() before and after each test case"),
        ('jobs=', 'j', "Number of local workers to run, a strictly positive integer"),
        ('profile', None, "Run tests under the Python profiler"),
        ('random=', 'Z', "Run tests in random order using the specified seed"),
        ('reactor=', 'r', "Which reactor to use"),
        ('reporter=', None, "Customize Trial's output with a reporter plugin"),
        ('rterrors', 'e', "Realtime errors: print out tracebacks as soon as they occur"),
        ('spew', None, "Print an insanely verbose log of everything that happens"),
        ('testmodule=', None, "Filename to grep for test cases (-*- test-case-name)"),
        ('tbformat=', None, ("Specify the format to display tracebacks with. Valid "
                             "formats are 'plain', 'emacs', and 'cgitb' which uses "
                             "the nicely verbose stdlib cgitb.text function")),
        ('unclean-warnings', None, "Turn dirty reactor errors into warnings"),
        ('until-failure', 'u', "Repeat a test (specified by -s) until it fails."),
        ('without-module=', None, ("Fake the lack of the specified modules, separated "
                                   "with commas")),
    ]
    boolean_options = ['debug', 'debug-stacktraces', 'disablegc', 'force-gc',
                       'profile', 'rterrors', 'spew', 'unclean-warnings',
                       'until-failure']

    def initialize_options(self):
        self.debug = None
        self.debug_stacktraces = None
        self.debugger = None
        self.disablegc = None
        self.force_gc = None
        self.jobs = None
        self.profile = None
        self.random = None
        self.reactor = None
        self.reporter = None
        self.rterrors = None
        self.spew = None
        self.testmodule = None
        self.tbformat = None
        self.unclean_warnings = None
        self.until_failure = None
        self.without_module = None

    def finalize_options(self):
        build = self.get_finalized_command('build')
        self.build_purelib = build.build_purelib
        self.build_platlib = build.build_platlib

    def run(self):
        self.run_command('build')
        old_path = sys.path[:]
        sys.path[0:0] = [self.build_purelib, self.build_platlib]

        result = 1
        try:
            result = self.run_tests()
        finally:
            sys.path = old_path
            raise SystemExit(result)

    def run_tests(self):
        # We do the import from Twisted inside the function instead of the top
        # of the file because since Twisted is a setup_requires, we can't
        # assume that Twisted will be installed on the user's system prior, so
        # if we don't do the import here, then importing from this plugin will
        # fail.
        from twisted.scripts import trial

        if not self.testmodule:
            self.testmodule = "farfetchd.test"

        # Handle parsing the trial options passed through the setuptools
        # trial command.
        cmd_options = []
        for opt in self.boolean_options:
            if getattr(self, opt.replace('-', '_'), None):
                cmd_options.append('--%s' % opt)

        for opt in ('debugger', 'jobs', 'random', 'reactor', 'reporter',
                    'testmodule', 'tbformat', 'without-module'):
            value = getattr(self, opt.replace('-', '_'), None)
            if value is not None:
                cmd_options.extend(['--%s' % opt, value])

        config = trial.Options()
        config.parseOptions(cmd_options)
        config['tests'] = [self.testmodule,]

        trial._initialDebugSetup(config)
        trialRunner = trial._makeRunner(config)
        suite = trial._getSuite(config)

        # run the tests
        if self.until_failure:
            test_result = trialRunner.runUntilFailure(suite)
        else:
            test_result = trialRunner.run(suite)

        if test_result.wasSuccessful():
            return 0  # success
        return 1      # failure


# If there is an environment variable FARFETCHD_INSTALL_DEPENDENCIES=0, it will
# disable checking for, fetching, and installing farfetchd's dependencies with
# easy_install.
#
# Setting FARFETCHD_INSTALL_DEPENDENCIES=0 is *highly* recommended, because
# easy_install is a security nightmare.  Automatically installing dependencies
# is enabled by default, however, because this is how all Python packages are
# supposed to work.
if bool(int(os.environ.get("FARFETCHD_INSTALL_DEPENDENCIES", 1))):
    requires, deplinks = get_requirements()
else:
    requires, deplinks = [], []


setuptools.setup(
    name='farfetchd',
    version=versioneer.get_version(),
    description='Twisted Python CAPTCHA server',
    author='Isis Agora Lovecruft',
    author_email='isis@torproject.org',
    maintainer='Isis Agora Lovecruft',
    maintainer_email='isis@torproject.org',
    url='https://www.torproject.org',
    download_url='https://gitweb.torproject.org/farfetchd.git',
    package_dir={'farfetchd': 'farfetchd'},
    packages=['farfetched',],
    scripts=['scripts/farfetched'],
    cmdclass=get_cmdclass(),
    include_package_data=True,
    install_requires=requires,
    dependency_links=deplinks,
)
