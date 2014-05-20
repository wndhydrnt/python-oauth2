# Run All unit tests
test:
	nosetests

unittest:
	nosetests --exclude='integration'

functest:
	nosetests --where=oauth2/test/integration