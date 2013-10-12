from oauth2.test import unittest
from oauth2.tokengenerator import URandomTokenGenerator

class URandomTokenGeneratorTestCase(unittest.TestCase):
    def test_generate(self):
        length = 20
        
        generator = URandomTokenGenerator(length=length)
        
        result = generator.generate()
        
        self.assertTrue(isinstance(result, str))
        self.assertEqual(len(result), length)

if __name__ == "__main__":
    unittest.main()
