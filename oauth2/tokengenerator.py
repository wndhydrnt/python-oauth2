"""
Provides various implementations of algorithms to generate a token.
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

        :param expires_in: Timeframe in seconds that defines how long a
                           generated token will be valid. Default: 0
        """
        self.expires_in = 0

    def create_access_token_data(self):
        """
        Create data needed by an access token.

        :return: A ``dict`` containing he ``access_token`` and the
                 ``token_type``. If the value of ``TokenGenerator.expires_in``
                 is larger than 0, a ``refresh_token`` will be generated too.
        """
        result = {"access_token": self.generate(), "token_type": "Bearer"}

        if self.expires_in > 0:
            result["refresh_token"] = self.generate()
            result["expires_in"] = self.expires_in

        return result

    def generate(self):
        """
        Implemented by generators extending this base class.
        """
        raise NotImplementedError


class URandomTokenGenerator(TokenGenerator):
    """
    Create a token using ``os.urandom()``.
    """
    def __init__(self, length=40):
        self.token_length = length
        TokenGenerator.__init__(self)

    def generate(self):
        """
        Returns a new token.
        """
        random_data = os.urandom(100)

        hash_gen = hashlib.new("sha512")
        hash_gen.update(random_data)

        return hash_gen.hexdigest()[:self.token_length]


class Uuid4(TokenGenerator):
    """
    Generate a token using uuid4.
    """
    def generate(self):
        """
        Returns a new token.
        """
        return str(uuid.uuid4())
