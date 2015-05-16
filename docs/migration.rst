Migration
=========

0.7.0 -> 1.0.0
--------------

One site adapter per grant
^^^^^^^^^^^^^^^^^^^^^^^^^^

Starting from ``1.0.0``, the grants
:class:`oauth2.grant.AuthorizationCodeGrant`,
:class:`oauth2.grant.ImplicitGrant` and
:class:`oauth2.grant.ResourceOwnerGrant` expect the parameter ``site_adapter``
to be passed to them.

:class:`oauth2.Provider` does not accept the parameter ``site_adapter``
anymore.

The base class ``oauth2.web.SiteAdapter`` does not exist anymore.

Code that looks like this in version ``0.7.0``

.. code-block:: python

   from oauth2 import Provider
   from oauth2.web import SiteAdapter
   from oauth2.grant import AuthorizationCodeGrant

   class ExampleSiteAdapter(SiteAdapter):
       ...

   provider = Provider(
       ...,
       site_adapter=ExampleSiteAdapter(),
       ...
   )
   provider.add_grant(AuthorizationCodeGrant())

has to be rewritten to look similar to the following

.. code-block:: python

   from oauth2 import Provider
   from oauth2.web import AuthorizationCodeGrantSiteAdapter
   from oauth2.grant import AuthorizationCodeGrant

   class ExampleSiteAdapter(AuthorizationCodeGrantSiteAdapter):
       # Override the methods defined in AuthorizationCodeGrantSiteAdapter to suite your needs
       ...

   # No site_adapter anymore
   provider = Provider(...)

   provider.add_grant(AuthorizationCodeGrant(site_adapter=ExampleSiteAdapter()))


WSGI adapter classes refactoring
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

All code to connect ``python-oauth2`` with a WSGI compliant server has been
moved to the module ``oauth2.web.wsgi``.

Also the class ``Wsgi`` has been renamed to ``Application`` and now expects
the parameter ``provider`` instead of ``server``.

Before:

.. code-block:: python

    from oauth2.web import Wsgi

    # Instantiating storage and provider...

    app = Wsgi(server=provider)


After:

.. code-block:: python

    from oauth2.web.wsgi import Application

    # Instantiating storage and provider...

    app = Application(provider=provider)
