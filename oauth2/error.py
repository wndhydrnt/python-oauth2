"""
Errors raised during the OAuth 2.0 flow.
"""

class AuthCodeNotFound(Exception):
    """
    Error indicating that an authorization code could not be read from the
    storage backend by an instance of :class:`oauth2.store.AuthCodeStore`.
    """
    pass

class ClientNotFoundError(Exception):
    """
    Error raised by an implementation of :class:`oauth2.store.ClientStore` if a
    client does not exists.
    """
    pass

class OAuthBaseError(Exception):
    """
    Base class used by all OAuth 2.0 errors.
    
    :param error: Identifier of the error.
    :param error_uri: Set this to delivery an URL to your documentation that
                      describes the error. (optional)
    :param explanation: Short message that describes the error. (optional)
    """
    def __init__(self, error, error_uri=None, explanation=None):
        self.error       = error
        self.error_uri   = error_uri
        self.explanation = explanation
        
        super(OAuthBaseError, self).__init__()

class OAuthClientError(OAuthBaseError):
    """
    Indicates an error during recognition of a client.
    """
    pass

class OAuthUserError(OAuthBaseError):
    """
    Indicates that the user denied authorization.
    """
    pass

class OAuthInvalidError(OAuthBaseError):
    """
    Indicates an error during validation of a request.
    """
    pass

class UserNotAuthenticated(Exception):
    """
    Raised by a :class:`oauth2.web.SiteAdapter` if a user could not be
    authenticated.
    """
    pass
