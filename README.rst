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
Also some features like `Refreh Tokens <http://tools.ietf.org/html/rfc6749#section-1.5>`_
have not been implemented yet.

Installation
************

python-oauth2 is available on
`PyPI <http://pypi.python.org/pypi/python-oauth2/>`_.

    pip install python-oauth2

Usage
*****

Example HTTP server::
    
    from wsgiref.simple_server import make_server
    import oauth2
    import oauth2.store
    import oauth2.web

    # Create a SiteAdapter to interact with the user.
    # This can be used to display confirmation dialogues.
    class TestSiteAdapter(oauth2.web.SiteAdapter):
        def authenticate(self, request, environ, scopes):
            # Always returning anything else than None here means the token
            # will be issued without any user interaction
            return {}

    # Create an in-memory storage to store your client apps.
    client_store = oauth2.store.LocalClientStore()
    # Add a client
    client_store.add_client(client_id="abc", client_secret="xyz",
                            redirect_uris=["http://localhost/callback"])
    
    # Create an in-memory storage to store issued tokens.
    token_store = oauth2.store.LocalTokenStore()

    # Create the controller.
    auth_controller = oauth2.AuthorizationController(
        # LocalTokenStore can store access and auth tokens
        access_token_store=token_store,
        auth_token_store=token_store,
        client_store=client_store,
        site_adapter=TestSiteAdapter(),
        token_generator=oauth2.tokengenerator.Uuid4()
    )

    # Wrap the controller with the Wsgi adapter
    app = oauth2.web.Wsgi(server=auth_controller)

    httpd = make_server('', 8080, app)
    httpd.server_forever()

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

Like for storage, python-oauth2 does not define how you identify a user or
show a confirmation dialogue.
Instead your application should use the API defined by
``oauth2.web.SiteAdapter``.

Changelog
*********

New in version 0.2.0
====================
- Support for scopes
- Local token and client stores
- Memcache token store
- Support for Python 2.6, 3.2 and 3.3

New in version 0.1.0
====================
- Working implementation of Authorization Code Grant
- Working implementation of Implicit Grant
- Working implementation of Resource Owner Password Credentials Grant
