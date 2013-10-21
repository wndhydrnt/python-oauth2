``oauth2.store`` --- Storing and retrieving data
================================================

.. automodule:: oauth2.store

Data types
----------

.. autoclass:: oauth2.AccessToken

.. autoclass:: oauth2.AuthorizationCode

.. autoclass:: oauth2.Client

Base classes
------------

.. autoclass:: AccessTokenStore
   :members:

.. autoclass:: AuthCodeStore
   :members:

.. autoclass:: ClientStore
   :members:

Concrete classes
----------------

.. autoclass:: LocalClientStore
   :show-inheritance:
   :members:

.. autoclass:: LocalTokenStore
   :show-inheritance:
   :members:

.. autoclass:: MemcacheTokenStore
   :show-inheritance:
   :members:
