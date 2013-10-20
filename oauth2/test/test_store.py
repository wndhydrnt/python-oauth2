import unittest
from oauth2.store import MemcacheTokenStore, LocalTokenStore, LocalClientStore
from mock import Mock

class LocalClientStoreTestCase(unittest.TestCase):
    def test_add_client_and_fetch_by_client_id(self):
        expected_client_data = {"client_id": "abc", "client_secret": "xyz",
                                "redirect_uris": ["http://localhost"]}
        
        store = LocalClientStore()
        
        success = store.add_client(expected_client_data["client_id"],
                                   expected_client_data["client_secret"],
                                   expected_client_data["redirect_uris"])
        self.assertTrue(success)
        
        client = store.fetch_by_client_id("abc")
        
        self.assertDictEqual(client, expected_client_data)

class LocalTokenStoreTestCase(unittest.TestCase):
    def setUp(self):
        self.access_token = "xyz"
        self.access_token_data = {"client_id": "myclient",
                                  "scopes": ["foo_read", "foo_write"],
                                  "user_data": {"name": "test"}}
        self.auth_code_data = {"client_id": "myclient", "code": "abc",
                               "expired_at": 100,
                               "redirect_uri": "http://localhost",
                               "scopes": ["foo_read", "foo_write"],
                               "user_data": {"name": "test"}}
        
        self.test_store = LocalTokenStore()
    
    def test_save_code_and_fetch_by_code(self):
        success = self.test_store.save_code(self.auth_code_data["client_id"],
                                            self.auth_code_data["code"],
                                            self.auth_code_data["expired_at"],
                                            self.auth_code_data["redirect_uri"],
                                            self.auth_code_data["scopes"],
                                            self.auth_code_data["user_data"])
        self.assertTrue(success)
        
        result = self.test_store.fetch_by_code(self.auth_code_data["code"])
        
        self.assertEqual(result, self.auth_code_data)
    
    def test_save_token_and_fetch_by_token(self):
        success = self.test_store.save_token(self.access_token_data["client_id"],
                                             self.access_token_data["scopes"],
                                             self.access_token,
                                             self.access_token_data["user_data"])
        self.assertTrue(success)
        
        result = self.test_store.fetch_by_token(self.access_token)
        
        self.assertDictEqual(result, self.access_token_data)

class MemcacheTokenStoreTestCase(unittest.TestCase):
    def setUp(self):
        self.cache_prefix = "test"
    
    def _generate_test_cache_key(self, key):
        return self.cache_prefix + "_" + key
    
    def test_fetch_by_code(self):
        code = "abc"
        expected_result = {"client_id": "myclient", "code": code,
                           "expired_at": 100,
                           "redirect_uri": "http://localhost",
                           "scopes": ["foo_read", "foo_write"],
                           "user_data": {"name": "test"}}
        
        mc_mock = Mock(spec=["get"])
        mc_mock.get.return_value = expected_result
        
        store = MemcacheTokenStore(mc=mc_mock, prefix=self.cache_prefix)
        
        result = store.fetch_by_code(code)
        
        mc_mock.get.assert_called_with(self._generate_test_cache_key(code))
        self.assertEqual(result, expected_result)
    
    def test_save_code(self):
        data = {"client_id": "myclient", "code": "abc", "expired_at": 100,
                 "redirect_uri": "http://localhost",
                 "scopes": ["foo_read", "foo_write"],
                 "user_data": {"name": "test"}}
        cache_key = self._generate_test_cache_key(data["code"])
        
        mc_mock = Mock(spec=["set"])
        
        store = MemcacheTokenStore(mc=mc_mock, prefix=self.cache_prefix)
        
        store.save_code(data["client_id"], data["code"], data["expired_at"],
                        data["redirect_uri"], data["scopes"],
                        data["user_data"])
        
        mc_mock.set.assert_called_with(cache_key, data)
    
    def test_save_token(self):
        token = "xyz"
        data = {"client_id": "myclient", "scopes": ["foo_read", "foo_write"],
                "user_data": {"name": "test"}}
        cache_key = self._generate_test_cache_key(token)
        
        mc_mock = Mock(spec=["set"])
        
        store = MemcacheTokenStore(mc=mc_mock, prefix=self.cache_prefix)
        
        store.save_token(data["client_id"], data["scopes"], token,
                         data["user_data"])
        
        mc_mock.set.assert_called_with(cache_key, data)