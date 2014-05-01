``oauth2.store`` --- Storing and retrieving data
================================================

.. automodule:: oauth2.store

Data types
----------

.. autoclass:: oauth2.datatype.AccessToken

.. autoclass:: oauth2.datatype.AuthorizationCode

.. autoclass:: oauth2.datatype.Client

Base classes
------------

.. autoclass:: AccessTokenStore
   :members:

.. autoclass:: AuthCodeStore
   :members:

.. autoclass:: ClientStore
   :members:

Implementations
---------------

.. toctree::
   :maxdepth: 2

   store/memcache.rst
   store/memory.rst
   store/mongodb.rst
   store/redisdb.rst
   store/dbapi.rst
   store/mysql.rst
