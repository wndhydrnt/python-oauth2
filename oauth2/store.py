"""
Store adapters to persist data during the OAuth 2.0 process.
"""
from oauth2.error import ClientNotFoundError

class AccessTokenStore(object):
    """
    Base class for persisting an access token after it has been generated.
    
    Used by two-legged and three-legged authentication flows.
    """
    def save_token(self, client_id, scopes, token, user_data):
        """
        Stores the access token and additional data.
        
        :param client_id: Identifier of the client the token is issued.
        :param scopes: List of scopes requested by a client.
        :param token: The access token.
        :param user_data: Dictionary containing additional data to save with
                          the token.
        
        """
        raise NotImplementedError

class AuthTokenStore(object):
    """
    Base class for writing and retrieving an auth token during three-legged
    OAuth2 requests.
    """
    def fetch_by_code(self, code):
        """
        Returns a hash of data belonging to an auth token. Should return
        ``None`` if no data was found.
        
        :param code: The authorization code.
        
        """
        raise NotImplementedError
    
    def save_code(self, client_id, code, expires_at, redirect_uri, scopes,
                  user_data):
        """
        Stores the data belonging to an authorization code token.
        
        :param client_id: Identifier of the client the token is issued.
        :param code: The authorization code.
        :param expires_at: ``datetime.datetime`` the authorization code will
                           expire.
        :param redirect_uri: Redirect URI used in the token request.
        :param scopes: List of scopes requested by a client.
        :param user_data: Dictionary containing additional data to save with
                          the token.
        
        """
        raise NotImplementedError

class ClientStore(object):
    """
    Base class for handling OAuth2 clients.
    """
    def fetch_by_client_id(self, client_id):
        """
        Retrieve data of a client by its client identifier.
        
        :param client_id: Identifier of a client app.
        :return: An instance of ``oauth2.Client``.
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
        :param client_secret: Secret the client app uses for authentication against the OAuth 2.0 server.
        :param redirect_uris: A list of URIs to redirect to.
        
        """
        self.clients[client_id] = {"client_id": client_id,
                                   "client_secret": client_secret,
                                   "redirect_uris": redirect_uris}
        
        return True
    
    def fetch_by_client_id(self, client_id):
        if client_id not in self.clients:
            raise ClientNotFoundError
        
        return self.clients[client_id]

class LocalTokenStore(AccessTokenStore, AuthTokenStore):
    """
    Store tokens in memory.
    
    Useful for testing purposes or APIs with a very limited set of clients.
    Use memcache or redis as storage to be able to scale.
    """
    def __init__(self):
        self.access_tokens = {}
        self.auth_codes   = {}
    
    def fetch_by_code(self, code):
        if code not in self.auth_codes:
            return None
        
        return self.auth_codes[code]
    
    def save_code(self, client_id, code, expires_at, redirect_uri, scopes,
                  user_data):
        self.auth_codes[code] = {"client_id": client_id, "code": code,
                                  "expired_at": expires_at,
                                  "redirect_uri": redirect_uri,
                                  "scopes": scopes, "user_data": user_data}
        
        return True
    
    def save_token(self, client_id, scopes, token, user_data):
        self.access_tokens[token] = {"client_id": client_id, "scopes": scopes,
                                     "user_data": user_data}
        
        return True
    
    def fetch_by_token(self, token):
        """
        Returns data associated with an access token or ``None`` if no data was
        found.
        """
        if token not in self.access_tokens:
            return None
        
        return self.access_tokens[token]

class MemcacheTokenStore(AccessTokenStore, AuthTokenStore):
    """
    Store class that uses memcache to store access tokens and auth tokens.
    
    This Store supports ``pylibmc`` and ``python-memcached``. It tries to use
    ``pylibmc`` first and falls back to ``python-memcached``. Arguments are
    passed to the underlying client implementation.
    
    Initialization by passing an object::
        
        # This exmple uses python-memcached
        import memcache
        
        mc = memcache.Client(servers=['127.0.0.1:11211'], debug=0)
        
        token_store = MemcacheTokenStore(mc=mc)
    
    Initialization using pylibmc::
        
        token_store = MemcacheTokenStore(servers=["127.0.0.1"], binary=True,
                                         behaviors={"tcp_nodelay": True,
                                        "ketama": True})
        
    Initialization using python-memcached::
        
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
        
        See ``oauth2.store.AuthTokenStore``.
        
        """
        return self.mc.get(self._generate_cache_key(code))
    
    def save_code(self, client_id, code, expired_at, redirect_uri, scopes,
                  user_data):
        """
        Stores the data belonging to an authorization code token in memcache.
        
        See ``oauth2.store.AuthTokenStore``.
        
        """
        key = self._generate_cache_key(code)
        
        self.mc.set(key, {"client_id": client_id, "code": code,
                          "expired_at": expired_at,
                          "redirect_uri": redirect_uri, "scopes": scopes,
                          "user_data": user_data})
    
    def save_token(self, client_id, scopes, token, user_data):
        """
        Stores the access token and additional data in memcache.
        
        See ``oauth2.store.AccessTokenStore``.
        
        """
        key = self._generate_cache_key(token)
        
        self.mc.set(key, {"client_id": client_id, "scopes": scopes,
                          "user_data": user_data})
    
    def _generate_cache_key(self, identifier):
        return self.prefix + "_" + identifier
