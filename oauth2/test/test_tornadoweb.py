
import unittest
from mock import Mock
from tornado.web import MissingArgumentError, RequestHandler
from oauth2.tornadoweb import Request

class RequestTestCase(unittest.TestCase):
    def test_get_param_param_exists(self):
        """
        Request returns the value of a parameter when it is present
        """
        param = "abc"
        value = "xyz"
        
        tornado_request_mock = Mock()
        tornado_request_mock.method = "GET"
        
        request_handler_mock = Mock(RequestHandler)
        request_handler_mock.request = tornado_request_mock
        request_handler_mock.get_argument.return_value = value
        
        request = Request(request_handler_mock)
        
        result = request.get_param(param)
        
        request_handler_mock.get_argument.assert_called_with(param)
        self.assertEqual(result, value)
    
    def test_get_param_return_default_if_missing(self):
        """
        Request returns the default value on parameter not present
        """
        param   = "abc"
        default = "def"
        
        tornado_request_mock = Mock()
        tornado_request_mock.method = "GET"
        
        request_handler_mock = Mock(RequestHandler)
        request_handler_mock.request = tornado_request_mock
        request_handler_mock.get_argument.side_effect = MissingArgumentError(param)
        
        request = Request(request_handler_mock)
        
        result = request.get_param(name=param, default=default)
        
        self.assertEqual(result, default)
    
    def test_get_param_none_on_wrong_source(self):
        """
        Request returns 'None' on wrong request method
        """
        tornado_request_mock = Mock()
        tornado_request_mock.method = "POST"
        
        request_handler_mock = Mock(RequestHandler)
        request_handler_mock.request = tornado_request_mock
        
        request = Request(request_handler_mock)
        
        result = request.get_param(name="abc", default="def")
        
        self.assertEqual(result, None)
