from oauth2.test import unittest
from oauth2.store import MemcacheTokenStore, LocalTokenStore, LocalClientStore
from mock import Mock
from oauth2.error import ClientNotFoundError, AuthCodeNotFound
from oauth2 import AuthorizationCode, AccessToken

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
        
        self.assertEqual(client.identifier, expected_client_data["client_id"])
        self.assertEqual(client.secret, expected_client_data["client_secret"])
        self.assertEqual(client.redirect_uris, expected_client_data["redirect_uris"])
    
    def test_fetch_by_client_id_no_client(self):
        store = LocalClientStore()
        
        with self.assertRaises(ClientNotFoundError):
            store.fetch_by_client_id("abc")

class LocalTokenStoreTestCase(unittest.TestCase):
    def setUp(self):
        self.access_token_data = {"client_id": "myclient",
                                  "token": "xyz",
                                  "scopes": ["foo_read", "foo_write"],
                                  "data": {"name": "test"}}
        self.auth_code = AuthorizationCode("myclient", "abc", 100,
                                           "http://localhost",
                                           ["foo_read", "foo_write"],
                                           {"name": "test"})
        
        self.test_store = LocalTokenStore()
    
    def test_fetch_by_code(self):
        with self.assertRaises(AuthCodeNotFound):
            self.test_store.fetch_by_code("unknown")
    
    def test_save_code_and_fetch_by_code(self):
        success = self.test_store.save_code(self.auth_code)
        self.assertTrue(success)
        
        result = self.test_store.fetch_by_code(self.auth_code.code)
        
        self.assertEqual(result, self.auth_code)
    
    def test_save_token_and_fetch_by_token(self):
        access_token = AccessToken(**self.access_token_data)
        
        success = self.test_store.save_token(access_token)
        self.assertTrue(success)
        
        result = self.test_store.fetch_by_token(access_token.token)
        
        self.assertEqual(result, access_token)

class MemcacheTokenStoreTestCase(unittest.TestCase):
    def setUp(self):
        self.cache_prefix = "test"
    
    def _generate_test_cache_key(self, key):
        return self.cache_prefix + "_" + key
    
    def test_fetch_by_code(self):
        code = "abc"
        saved_data = {"client_id": "myclient", "code": code,
                      "expires_at": 100, "redirect_uri": "http://localhost",
                      "scopes": ["foo_read", "foo_write"],
                      "data": {"name": "test"}}
        
        mc_mock = Mock(spec=["get"])
        mc_mock.get.return_value = saved_data
        
        store = MemcacheTokenStore(mc=mc_mock, prefix=self.cache_prefix)
        
        auth_code = store.fetch_by_code(code)
        
        mc_mock.get.assert_called_with(self._generate_test_cache_key(code))
        self.assertEqual(auth_code.client_id, saved_data["client_id"])
        self.assertEqual(auth_code.code, saved_data["code"])
        self.assertEqual(auth_code.expires_at, saved_data["expires_at"])
        self.assertEqual(auth_code.redirect_uri, saved_data["redirect_uri"])
        self.assertEqual(auth_code.scopes, saved_data["scopes"])
        self.assertEqual(auth_code.data, saved_data["data"])
    
    def test_fetch_by_code_no_data(self):
        mc_mock = Mock(spec=["get"])
        mc_mock.get.return_value = None
        
        store = MemcacheTokenStore(mc=mc_mock, prefix=self.cache_prefix)
        
        with self.assertRaises(AuthCodeNotFound):
            store.fetch_by_code("abc")
    
    def test_save_code(self):
        data = {"client_id": "myclient", "code": "abc", "expires_at": 100,
                 "redirect_uri": "http://localhost",
                 "scopes": ["foo_read", "foo_write"],
                 "data": {"name": "test"}}
        
        auth_code = AuthorizationCode(**data)
        
        cache_key = self._generate_test_cache_key(data["code"])
        
        mc_mock = Mock(spec=["set"])
        
        store = MemcacheTokenStore(mc=mc_mock, prefix=self.cache_prefix)
        
        store.save_code(auth_code)
        
        mc_mock.set.assert_called_with(cache_key, data)
    
    def test_save_token(self):
        data = {"client_id": "myclient", "token": "xyz",
                "data": {"name": "test"}, "scopes": ["foo_read", "foo_write"]}
        
        access_token = AccessToken(**data)
        
        cache_key = self._generate_test_cache_key(access_token.token)
        
        mc_mock = Mock(spec=["set"])
        
        store = MemcacheTokenStore(mc=mc_mock, prefix=self.cache_prefix)
        
        store.save_token(access_token)
        
        mc_mock.set.assert_called_with(cache_key, data)