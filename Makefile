
API.html:
	pygmentize -S default -f html -a .highlight > style.css
	rst2html.py --stylesheet style.css API.rst farfetched/API.html

clean:
	-rm style.css
	-rm API.html

test:
	python setup.py test
