import asynctest
import unittest.mock as mock

import asyncwhois


class TestAsyncWhoIsQuery(asynctest.TestCase):

    @mock.patch('asyncwhois.pywhois.PyWhoIs._aio_from_url')
    async def test_aio_lookup(self, mock_whois_call):
        mock_query_data = {'parser_output': {'domain_name': 'amazon.com'}, 'query_output': 'Domain Name: amazon.com'}
        mock_whois_call.return_value = mock.Mock(query_output=mock_query_data.get('query_output'),
                                                 parser_output=mock_query_data.get('parser_output'))
        test_domain = "amazon.com"
        w = await asyncwhois.aio_lookup(test_domain)
        mock_whois_call.assert_called_once()
        self.assertIn(f"domain name: {test_domain}", w.query_output.lower())
        self.assertEqual(w.parser_output.get('domain_name').lower(), test_domain)

    @mock.patch('asyncwhois.pywhois.PyWhoIs._from_url')
    def test_lookup(self, mock_whois_call):
        mock_query_data = {'parser_output': {'domain_name': 'elastic.co'}, 'query_output': 'Domain Name: elastic.co'}
        mock_whois_call.return_value = mock.Mock(query_output=mock_query_data.get('query_output'),
                                                 parser_output=mock_query_data.get('parser_output'))
        test_domain = "elastic.co"
        w = asyncwhois.lookup(test_domain)
        mock_whois_call.assert_called_once()
        self.assertIn(f"domain name: {test_domain}", w.query_output.lower())
        self.assertEqual(w.parser_output.get('domain_name').lower(), test_domain)

    @mock.patch('asyncwhois.pywhois.PyWhoIs._aio_from_whois_cmd')
    async def test_aio_whois_cmd_shell(self, mock_whois_call):
        mock_query_data = {'parser_output': {'domain_name': 'yahoo.com'}, 'query_output': 'Domain Name: yahoo.com'}
        mock_whois_call.return_value = mock.Mock(query_output=mock_query_data.get('query_output'),
                                                 parser_output=mock_query_data.get('parser_output'))
        test_domain = "yahoo.com"
        w = await asyncwhois.aio_whois_cmd_shell(test_domain)
        mock_whois_call.assert_called_once()
        self.assertIn(f"domain name: {test_domain}", w.query_output.lower())
        self.assertEqual(w.parser_output.get('domain_name').lower(), test_domain)

    @mock.patch('asyncwhois.pywhois.PyWhoIs._from_whois_cmd')
    def test_whois_cmd_shell(self, mock_whois_call):
        mock_query_data = {'parser_output': {'domain_name': 'comcast.net'}, 'query_output': 'Domain Name: comcast.net'}
        mock_whois_call.return_value = mock.Mock(query_output=mock_query_data.get('query_output'),
                                                 parser_output=mock_query_data.get('parser_output'))
        test_domain = "comcast.net"
        w = asyncwhois.whois_cmd_shell(test_domain)
        mock_whois_call.assert_called_once()
        self.assertIn(f"domain name: {test_domain}", w.query_output.lower())
        self.assertEqual(w.parser_output.get('domain_name').lower(), test_domain)

    def test_has_parser_support(self):
        not_supported = 'zzz'
        self.assertFalse(asyncwhois.has_parser_support(not_supported))
        supported = 'com'
        self.assertTrue(asyncwhois.has_parser_support(supported))