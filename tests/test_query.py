import unittest
import unittest.mock as mock

import asyncwhois.query
from asyncwhois.errors import WhoIsQueryConnectError


class TestWhoIsQuery(unittest.TestCase):

    @mock.patch('asyncwhois.query.socket')
    def test_whois_query_create_connection(self, mock_socket_lib):
        # test connect
        test_address_tuple_param = ('0.0.0.0', 69)
        test_timeout_param = 10
        # call WhoIsQuery's "_create_connection" method
        asyncwhois.query.WhoIsQuery._create_connection(test_address_tuple_param, test_timeout_param)
        mock_socket_lib.create_connection.assert_called()
        mock_socket_lib.create_connection.assert_called_with(address=test_address_tuple_param,
                                                             timeout=test_timeout_param)

    @mock.patch('asyncwhois.query.socket.socket')
    def test_whois_query_send_and_recv(self, mock_socket_instance):
        test_data_send_string = "a-domain-to-send"
        test_data_recv_bytes = b""  # empty so _send_and_recv does not infinite loop
        mock_socket_instance.recv.return_value = test_data_recv_bytes
        asyncwhois.query.WhoIsQuery._send_and_recv(mock_socket_instance, test_data_send_string)
        mock_socket_instance.recv.assert_called()
        mock_socket_instance.sendall.assert_called()
        mock_socket_instance.sendall.assert_called_with(test_data_send_string.encode())

    @mock.patch('asyncwhois.query.WhoIsQuery._send_and_recv')
    def test_whois_query_run(self, mock_send_recv):
        mock_send_recv.return_value = ""
        self.assertRaises(WhoIsQueryConnectError, asyncwhois.query.WhoIsQuery, "some-domain")


