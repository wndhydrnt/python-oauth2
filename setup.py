import os
import sys

from setuptools import setup
from oauth2 import VERSION

if sys.version_info < (3, 0, 0):
    memcache_require = "python-memcached"
else:
    memcache_require = "python3-memcached"

setup(name="python-oauth2",
      version=VERSION,
      description="OAuth 2.0 provider for python",
      long_description=open("README.rst").read(),
      author="Markus Meyer",
      author_email="hydrantanderwand@gmail.com",
      url="https://github.com/wndhydrnt/python-oauth2",
      packages=[d[0].replace("/", ".") for d in os.walk("oauth2") if not d[0].endswith("__pycache__")],
      extras_require={
        "memcache": [memcache_require],
        "mongodb": ["pymongo"],
        "redis": ["redis"]
      },
      classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.2",
        "Programming Language :: Python :: 3.3",
        "Programming Language :: Python :: 3.4",
        "Programming Language :: Python :: 3.5",
    ]
)
