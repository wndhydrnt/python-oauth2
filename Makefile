# Run All unit tests
test: unittest

unittest:
	nosetests --exclude='functional'

functest:
	nosetests --where=oauth2/test/functional
