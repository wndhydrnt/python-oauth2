import json
from mock import Mock
from oauth2.test import unittest
from oauth2 import AuthorizationController
from oauth2.store import ClientStore
from oauth2.web import Response, Request, SiteAdapter

class AuthorizationControllerTestCase(unittest.TestCase):
    def setUp(self):
        self.client_store_mock = Mock(spec=ClientStore)
        self.token_generator_mock = Mock()
        
        self.auth_server = AuthorizationController(access_token_store=Mock(),
                                               auth_code_store=Mock(),
                                               client_store=self.client_store_mock,
                                               site_adapter=Mock(),
                                               token_generator=self.token_generator_mock,
                                               response_class=Mock())
    
    def test_dispatch(self):
        environ        = {"session": "data"}
        process_result = "response"
        
        request_mock = Mock(spec=Request)
        
        response_mock = Mock(spec=Response)
        response_class_mock = Mock(return_value=response_mock)
        
        grant_handler_mock = Mock(spec=["process", "read_validate_params"])
        grant_handler_mock.process.return_value = process_result
        
        grant_factory_mock = Mock(return_value=grant_handler_mock)
        
        self.auth_server.response_class = response_class_mock
        self.auth_server.site_adapter = Mock(spec=SiteAdapter)
        self.auth_server.add_grant(grant_factory_mock)
        result = self.auth_server.dispatch(request_mock, environ)
        
        grant_factory_mock.assert_called_with(request_mock, self.auth_server)
        response_class_mock.assert_called_with()
        grant_handler_mock.read_validate_params.assert_called_with(request_mock)
        grant_handler_mock.process.assert_called_with(request_mock,
                                                      response_mock, environ)
        self.assertEqual(result, process_result)
    
    def test_dispatch_no_grant_type_found(self):
        error_body = {"error": "unsupported_response_type",
                      "error_description": "Server does not support given response_type"}
        
        request_mock = Mock(spec=Request)
        
        response_mock = Mock(spec=Response)
        response_class_mock = Mock(return_value=response_mock)
        
        self.auth_server.response_class = response_class_mock
        result = self.auth_server.dispatch(request_mock, {})
        
        response_mock.add_header.assert_called_with("Content-type",
                                                    "application/json")
        self.assertEqual(response_mock.status_code, 400)
        self.assertEqual(response_mock.body, json.dumps(error_body))
        self.assertEqual(result, response_mock)
