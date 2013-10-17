import re
from oauth2.test import unittest
from oauth2.tokengenerator import URandomTokenGenerator, Uuid4

class URandomTokenGeneratorTestCase(unittest.TestCase):
    def test_generate(self):
        length = 20
        
        generator = URandomTokenGenerator(length=length)
        
        result = generator.generate()
        
        self.assertTrue(isinstance(result, str))
        self.assertEqual(len(result), length)

class Uuid4TestCase(unittest.TestCase):
    def test_generate(self):
        generator = Uuid4()
        
        result = generator.generate()
        
        regex = re.compile(r"^[a-z0-9]{8}\-[a-z0-9]{4}\-[a-z0-9]{4}\-[a-z0-9]{4}-[a-z0-9]{12}$")
        
        match = regex.match(result)
        
        self.assertEqual(result, match.group())

if __name__ == "__main__":
    unittest.main()
