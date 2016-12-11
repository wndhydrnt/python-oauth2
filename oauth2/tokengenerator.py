"""
Provides various implementations of algorithms to generate an Access Token or
Refresh Token.
"""

import hashlib
import os
import uuid


class TokenGenerator(object):
    """
    Base class of every token generator.
    """

    def __init__(self):
        """
        Create a new instance of a token generator.
        """
        self.expires_in = {}
        self.refresh_expires_in = 0

    def create_access_token_data(self, data, grant_type, user_id):
        """
        Create data needed by an access token.

        :param data: Arbitrary data as returned by the ``authenticate()`` method of a ``SiteAdapter``.
        :type data: dict
        :param grant_type:
        :type grant_type: str
        :param user_id: Identifier of the current user as returned by the ``authenticate()`` method of a ``SiteAdapter``.
        :type user_id: int

        :return: A ``dict`` containing the ``access_token`` and the
                 ``token_type``. If the value of ``TokenGenerator.expires_in``
                 is larger than 0, a ``refresh_token`` will be generated too.
        :rtype: dict

        .. versionchanged:: 1.1.0
            New parameters ``data`` and ``user_id``
        """
        result = {"access_token": self.generate(data, user_id), "token_type": "Bearer"}

        if self.expires_in.get(grant_type, 0) > 0:
            result["refresh_token"] = self.generate()

            result["expires_in"] = self.expires_in[grant_type]

        return result

    def generate(self, data=None, user_id=None):
        """
        Implemented by generators extending this base class.

        :param data: Arbitrary data as returned by the ``authenticate()`` method of a ``SiteAdapter``.
        :type data: dict
        :param user_id: Identifier of the current user as returned by the ``authenticate()`` method of a ``SiteAdapter``.
        :type user_id: int

        :raises NotImplementedError:

        .. versionchanged:: 1.1.0
            New parameters ``data`` and ``user_id``
        """
        raise NotImplementedError


class URandomTokenGenerator(TokenGenerator):
    """
    Create a token using ``os.urandom()``.
    """

    def __init__(self, length=40):
        self.token_length = length
        TokenGenerator.__init__(self)

    def generate(self, data=None, user_id=None):
        """
        :return: A new token
        :rtype: str
        """
        random_data = os.urandom(100)

        hash_gen = hashlib.new("sha512")
        hash_gen.update(random_data)

        return hash_gen.hexdigest()[:self.token_length]


class Uuid4(TokenGenerator):
    """
    Generate a token using uuid4.
    """

    def generate(self, data=None, user_id=None):
        """
        :return: A new token
        :rtype: str
        """
        return str(uuid.uuid4())
