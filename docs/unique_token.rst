Unique Access Tokens
====================

This page explains the concepts of unique access tokens and how to enable this
feature.

What are unique access tokens?
------------------------------

When the use of unique access tokens is enabled the Provider will respond with
an existing access token to subsequent requests of a client instead of issuing
a new token on each request.

An existing access token will be returned if the following conditions are
met:

* The access token has been issued for the requesting client
* The access token has been issued for the same user as in the current request
* The requested scope is the same as in the existing access token
* The requested type is the same as in the existing access token

.. note::

    Unique access tokens are currently supported by
    :class:`oauth2.grant.AuthorizationCodeGrant` and
    :class:`oauth2.grant.ResourceOwnerGrant`.

Preconditions
-------------

As stated in the previous section, a unique access token is bound not only to a
client but also to a user. To make this work the Provider needs some kind of
identifier that is unique for each user (typically the ID of a user in the
database). The identifier is stored along with all the other information of an
access token. It has to be returned as the second item of a tuple by your
implementation of :class:`oauth2.web.SiteAdapter.authenticate`::

    class MySiteAdapter(SiteAdapter):

        def authenticate(self, request, environ, scopes):
            // Your logic here

            return None, user["id"]

Enabling the feature
--------------------

Unique access tokens are turned off by default. They can be turned on for each
grant individually::

    auth_code_grant = oauth2.grant.AuthorizationCodeGrant(unique_token=True)
    provider = oauth2.Provider() // Parameters omitted for readability
    provider.add_grant(auth_code_grant)

or you can enable them for all grants that support this feature after
initialization of :class:`oauth2.Provider`::

    provider = oauth2.Provider() // Parameters omitted for readability
    provider.enable_unique_tokens()

.. note::

    If you enable the feature but forgot to make
    :class:`oauth2.web.SiteAdapter.authenticate` return a user identifier, the
    Provider will respond with an error to requests for a token.
