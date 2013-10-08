"""
Errors of the OAuth 2.0 flow.
"""

class OAuthBaseError(Exception):
    """
    Base class used by all OAuth errors.
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
