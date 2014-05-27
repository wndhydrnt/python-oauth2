from setuptools import setup

VERSION = "0.8.0"

setup(name="python-oauth2",
      version=VERSION,
      description="OAuth 2.0 provider for python",
      long_description=open("README.rst").read(),
      author="Markus Meyer",
      author_email="hydrantanderwand@gmail.com",
      url="https://github.com/wndhydrnt/python-oauth2",
      packages=["oauth2", "oauth2.store", "oauth2.store.dbapi",
                "oauth2.test"],
      install_requires=["basicauth==0.2"],
      classifiers=[
        "Development Status :: 4 - Beta",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 2.6",
        "Programming Language :: Python :: 2.7",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.2",
        "Programming Language :: Python :: 3.3",
    ]
)
