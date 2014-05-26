# Run All unit tests
test:
	nosetests

unittest:
	nosetests --exclude='functional'

functest:
	nosetests --where=oauth2/test/functional
