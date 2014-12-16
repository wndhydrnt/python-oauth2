Migration
=========

0.7.0 --> 0.8.0
---------------

One site adapter per grant
^^^^^^^^^^^^^^^^^^^^^^^^^^

Starting from ``0.8.0``, the grants
:class:`oauth2.grant.AuthorizationCodeGrant`,
:class:`oauth2.grant.ImplicitGrant` and
:class:`oauth2.grant.ResourceOwnerGrant` expect the parameter ``site_adapter``
to be passed to them.

:class:`oauth2.Provider` does not accept the parameter ``site_adapter``.

``oauth2.web.SiteAdapter`` has been deleted.

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
       ...

   # No site_adapter anymore
   provider = Provider(...)

   provider.add_grant(AuthorizationCodeGrant(site_adapter=ExampleSiteAdapter()))
