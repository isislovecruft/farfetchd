===========
 farfetchd
===========

A service which creates CAPTCHA challenges and verifies their responses.

It is written in Twisted Python.

Install
--------

```
git clone https://github.com/isislovecruft/farfetchd
cd farfetchd
mkvirtualenv -a `pwd` farfetchd
pip install -r requirements.txt
python setup.py install
```

Running
--------

There is no configuration right now, other than the global variables in
server.py.  Edit those to change the host, port, and filename and directories
for keys and CAPTCHAs.

To generate a cache of local CAPTCHAs, see:
https://github.com/isislovecruft/gimp-captcha

To start the server, simply do:

```
farfetchd
```

It will stupidly log straight to stdout.

If you didn't do the `python setup.py setup` from the installation stage above,
you can also start the server with `python ./farfetchd/server.py`.

Bugs
-----

Please file an issue on Tor's Trac:
https://trac.torproject.org/projects/tor/newticket?type=defect&keywords=farfetchd&owner=isis

Contributing
-------------

Please see CONTRIBUTING.rst.
