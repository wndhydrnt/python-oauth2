python-oauth2
###############

.. image:: https://travis-ci.org/wndhydrnt/python-oauth2.png?branch=master
   :target: https://travis-ci.org/wndhydrnt/python-oauth2

python-oauth2 is a framework that aims at making it easy to provide authentication
via `OAuth 2.0 <http://tools.ietf.org/html/rfc6749>`_ within an application stack. 

Status
******

python-oauth2 is currently not ready for use in production environments.
While the basic implementations work already pretty well, some types of
authorization Grants
`defined in the RFC <http://tools.ietf.org/html/rfc6749#section-1.3>`_ are
still missing.
Also some features like `scopes <http://tools.ietf.org/html/rfc6749#section-3.3>`_ or
`Refreh Token <http://tools.ietf.org/html/rfc6749#section-1.5>`_ have not
been implemented yet.

Usage
*****

Storage adapters
================

python-oauth2 handles the request/response flow needed to create a OAuth 2.0 token.
It does not define how a token is stored so you can choose the
persistence strategy that works best for you. It is possible to write a token to
mysql or mongodb for persistence, save it in memcache or redis for fast access or
mix both approaches. This flexibility is achieved by the use of storage adapters
that define an interface which is called by a Grant handler during processing.

The ``oauth2.store`` module defines base classes for each type of storage.
Also take a look at the examples in the *examples* directory of the project.

Site adapter
============

Like for storage, python-oauth2 does not define how you identify a user or show a
confirmation dialogue.
Instead your application should use the API defined by ``oauth2.web.SiteAdapter``.
