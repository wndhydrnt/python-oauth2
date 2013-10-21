"""
Store adapters to persist and retrieve data during the OAuth 2.0 process or
for later use.
This module provides base classes that can be extended to implement your own
solution specific to your needs.
It also includes implementations for popular storage systems like memcache.
"""
from oauth2.error import ClientNotFoundError, AuthCodeNotFound
from oauth2 import AuthorizationCode, Client

class AccessTokenStore(object):
    """
    Base class for persisting an access token after it has been generated.
    
    Used in two-legged and three-legged authentication flows.
    """
    def save_token(self, access_token):
        """
        Stores an access token and additional data.
        
        :param access_token: An instance of :class:`oauth2.AccessToken`.
        
        """
        raise NotImplementedError

class AuthCodeStore(object):
    """
    Base class for writing and retrieving an auth token during the
    Authorization Code Grant flow.
    """
    def fetch_by_code(self, code):
        """
        Returns an AuthorizationCode fetched from a storage.
        
        :param code: The authorization code.
        :return: An instance of :class:`oauth2.AuthorizationCode`.
        :raises: :class:`AuthCodeNotFound` if no data could be retrieved for
                 given code.
        
        """
        raise NotImplementedError
    
    def save_code(self, authorization_code):
        """
        Stores the data belonging to an authorization code token.
        
        :param authorization_code: An instance of
                                   :class:`oauth2.AuthorizationCode`.
        
        """
        raise NotImplementedError

class ClientStore(object):
    """
    Base class for handling OAuth2 clients.
    """
    def fetch_by_client_id(self, client_id):
        """
        Retrieve a client by its identifier.
        
        :param client_id: Identifier of a client app.
        :return: An instance of :class:`oauth2.Client`.
        :raises: ClientNotFoundError
        
        """
        raise NotImplementedError

class LocalClientStore(ClientStore):
    """
    Stores clients in memory.
    """
    def __init__(self):
        self.clients = {}
    
    def add_client(self, client_id, client_secret, redirect_uris):
        """
        Add a client app.
        
        :param client_id: Identifier of the client app.
        :param client_secret: Secret the client app uses for authentication
                              against the OAuth 2.0 server.
        :param redirect_uris: A ``list`` of URIs to redirect to.
        
        """
        self.clients[client_id] = Client(identifier=client_id,
                                         secret=client_secret,
                                         redirect_uris=redirect_uris)
        
        return True
    
    def fetch_by_client_id(self, client_id):
        """
        Retrieve a client by its identifier.

        :param client_id: Identifier of a client app.
        :return: An instance of :class:`oauth2.Client`.
        :raises: ClientNotFoundError

        """
        if client_id not in self.clients:
            raise ClientNotFoundError
        
        return self.clients[client_id]

class LocalTokenStore(AccessTokenStore, AuthCodeStore):
    """
    Stores tokens in memory.
    
    Useful for testing purposes or APIs with a very limited set of clients.
    Use memcache or redis as storage to be able to scale.
    """
    def __init__(self):
        self.access_tokens = {}
        self.auth_codes   = {}
    
    def fetch_by_code(self, code):
        """
        Returns an AuthorizationCode.
        
        :param code: The authorization code.
        :return: An instance of :class:`oauth2.AuthorizationCode`.
        :raises: :class:`AuthCodeNotFound` if no data could be retrieved for
                 given code.
        
        """
        if code not in self.auth_codes:
            raise AuthCodeNotFound
        
        return self.auth_codes[code]
    
    def save_code(self, authorization_code):
        """
        Stores the data belonging to an authorization code token.
        
        :param authorization_code: An instance of
                                   :class:`oauth2.AuthorizationCode`.
        
        """
        self.auth_codes[authorization_code.code] = authorization_code
        
        return True
    
    def save_token(self, access_token):
        """
        Stores an access token and additional data in memory.
        
        :param client_id: An instance of :class:`oauth2.AccessToken`.
        """
        self.access_tokens[access_token.token] = access_token
        
        return True
    
    def fetch_by_token(self, token):
        """
        Returns data associated with an access token or ``None`` if no data
        was found.

        Useful for cases like validation where the access token needs to be
        read again.

        :param token: A access token code.
        :return: An instance of :class:`oauth2.AccessToken`.
        """
        if token not in self.access_tokens:
            return None
        
        return self.access_tokens[token]

class MemcacheTokenStore(AccessTokenStore, AuthCodeStore):
    """
    Uses memcache to store access tokens and auth tokens.
    
    This Store supports ``pylibmc`` and ``python-memcached``. It tries to use
    ``pylibmc`` first and falls back to ``python-memcached``. Arguments are
    passed to the underlying client implementation.
    
    Initialization by passing an object::
        
        # This example uses python-memcached
        import memcache
        
        # Somewhere in your application
        mc = memcache.Client(servers=['127.0.0.1:11211'], debug=0)
        # ...
        token_store = MemcacheTokenStore(mc=mc)
    
    Initialization using ``pylibmc``::
        
        token_store = MemcacheTokenStore(servers=["127.0.0.1"], binary=True,
                                         behaviors={"tcp_nodelay": True,
                                        "ketama": True})
        
    Initialization using ``python-memcached``::
        
        token_store = MemcacheTokenStore(servers=['127.0.0.1:11211'], debug=0)

    """
    def __init__(self, mc=None, prefix="oauth2", *args, **kwargs):
        self.prefix = prefix
        
        if mc is not None:
            self.mc = mc
        else:
            try:
                import pylibmc
                self.mc = pylibmc.Client(*args, **kwargs)
            except ImportError:
                import memcache
                self.mc = memcache.Client(*args, **kwargs)
    
    def fetch_by_code(self, code):
        """
        Returns data belonging to an authorization code from memcache or
        ``None`` if no data was found.
        
        See :class:`oauth2.store.AuthCodeStore`.
        
        """
        code_data = self.mc.get(self._generate_cache_key(code))
        
        if code_data is None:
            raise AuthCodeNotFound
        
        return AuthorizationCode(**code_data)
    
    def save_code(self, authorization_code):
        """
        Stores the data belonging to an authorization code token in memcache.
        
        See :class:`oauth2.store.AuthCodeStore`.
        
        """
        key = self._generate_cache_key(authorization_code.code)
        
        self.mc.set(key, authorization_code)
    
    def save_token(self, access_token):
        """
        Stores the access token and additional data in memcache.
        
        See :class:`oauth2.store.AccessTokenStore`.
        
        """
        key = self._generate_cache_key(access_token.token)
        
        self.mc.set(key, access_token)
    
    def _generate_cache_key(self, identifier):
        return self.prefix + "_" + identifier
