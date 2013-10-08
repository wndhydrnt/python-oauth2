import hashlib
import os
import uuid

class URandomTokenGenerator(object):
    def __init__(self, length=40):
        self.token_length = length
    
    def generate(self):
        randomData = os.urandom(100)
        
        hash_gen = hashlib.new("sha512")
        hash_gen.update(randomData)
        
        return hash_gen.hexdigest()[:self.token_length]

class Uuid4(object):
    def generate(self):
        return str(uuid.uuid4())
