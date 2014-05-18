python-oauth2
#############

python-oauth2 is a framework that aims at making it easy to provide authentication
via `OAuth 2.0 <http://tools.ietf.org/html/rfc6749>`_ within an application stack.

`Documentation <http://python-oauth2.readthedocs.org/en/latest/index.html>`_

Status
******

.. image:: https://travis-ci.org/wndhydrnt/python-oauth2.png?branch=master
   :target: https://travis-ci.org/wndhydrnt/python-oauth2

python-oauth2 has reached its beta phase. All main parts of the `OAuth 2.0 RFC <http://tools.ietf.org/html/rfc6749>`_ such as the various types of Grants, Refresh Token and Scopes have been implemented. However, bugs might occur or implementation details might be wrong.

Installation
************

python-oauth2 is available on
`PyPI <http://pypi.python.org/pypi/python-oauth2/>`_.

    pip install python-oauth2

Usage
*****

Example Authorization server

.. code-block:: python

    from wsgiref.simple_server import make_server
    import oauth2
    import oauth2.grant
    import oauth2.error
    import oauth2.store.memory
    import oauth2.tokengenerator
    import oauth2.web

    # Create a SiteAdapter to interact with the user.
    # This can be used to display confirmation dialogs and the like.
    class ExampleSiteAdapter(oauth2.web.SiteAdapter):
        def authenticate(self, request, environ, scopes):
            # Check if the user has granted access
            if request.post_param("confirm") == "confirm":
                return {}

            raise oauth2.error.UserNotAuthenticated

        def render_auth_page(self, request, response, environ, scopes):
            response.body = '''
    <html>
        <body>
            <form method="POST" name="confirmation_form">
                <input type="submit" name="confirm" value="confirm" />
                <input type="submit" name="deny" value="deny" />
            </form>
        </body>
    </html>'''
            return response

        def user_has_denied_access(self, request):
            # Check if the user has denied access
            if request.post_param("deny") == "deny":
                return True
            return False

    # Create an in-memory storage to store your client apps.
    client_store = oauth2.store.memory.ClientStore()
    # Add a client
    client_store.add_client(client_id="abc", client_secret="xyz",
                            redirect_uris=["http://localhost/callback"])

    # Create an in-memory storage to store issued tokens.
    # LocalTokenStore can store access and auth tokens
    token_store = oauth2.store.memory.TokenStore()

    # Create the controller.
    auth_controller = oauth2.Provider(
        access_token_store=token_store,
        auth_code_store=token_store,
        client_store=client_store,
        site_adapter=ExampleSiteAdapter(),
        token_generator=oauth2.tokengenerator.Uuid4()
    )

    # Add Grants you want to support
    auth_controller.add_grant(oauth2.grant.AuthorizationCodeGrant())
    auth_controller.add_grant(oauth2.grant.ImplicitGrant())

    # Add refresh token capability and set expiration time of access tokens
    # to 30 days
    auth_controller.add_grant(oauth2.grant.RefreshToken(expires_in=2592000))

    # Wrap the controller with the Wsgi adapter
    app = oauth2.web.Wsgi(server=auth_controller)

    if __name__ == "__main__":
        httpd = make_server('', 8080, app)
        httpd.serve_forever()

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
