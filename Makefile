.PHONY: install test
.DEFAULT: install test

TRIAL:=$(shell which trial)
VERSION:=$(shell git describe)

define PYTHON_WHICH
import platform
import sys
sys.stdout.write(platform.python_implementation())
endef

PYTHON_IMPLEMENTATION:=$(shell python -c '$(PYTHON_WHICH)')
PYTHON_PYTHON=CPython
PYTHON_PYPY=PyPy

all: uninstall clean install coverage-test

API.html:
	pygmentize -S default -f html -a .highlight > style.css
	rst2html.py --stylesheet style.css doc/API.rst farfetched/API.html

install:
	python setup.py install --record installed-files.txt

force-install:
	python setup.py install --force --record installed-files.txt

uninstall:
	touch installed-files.txt
	cat installed-files.txt | xargs rm -rf
	rm installed-files.txt

reinstall: uninstall force-install

clean:
	-rm style.css
	-rm API.html

test:
	python setup.py test

coverage-test:
ifeq ($(PYTHON_IMPLEMENTATION),PyPy)
	@echo "Detected PyPy... not running coverage."
	python setup.py test
else
	coverage run --rcfile=".coveragerc" $(TRIAL) ./farfetchd/test/test_*.py
	coverage report --rcfile=".coveragerc"
endif
