import asynctest
import unittest.mock as mock

import asyncwhois


class TestAsyncWhoIsQuery(asynctest.TestCase):

    @mock.patch('asyncwhois.query.AsyncWhoIsQuery')
    async def test_aio_lookup(self, mock_query):
        mock_query_data = {'parser_output': {'domain_name': 'amazon.com'}, 'query_output': 'Domain Name: amazon.com'}
        mock_query._from_aio_url.return_value = mock.Mock(data=mock_query_data)
        test_domain = "amazon.com"
        w = await asyncwhois.aio_lookup(test_domain)
        self.assertIn(f"domain name: {test_domain}", w.query_output.lower())
        self.assertEqual(w.parser_output.get('domain_name').lower(), test_domain)

    @mock.patch('asyncwhois.query.WhoIsQuery')
    def test_lookup(self, mock_query):
        mock_query_data = {'parser_output': {'domain_name': 'elastic.co'}, 'query_output': 'Domain Name: elastic.co'}
        mock_query._from_url.return_value = mock.Mock(data=mock_query_data)
        test_domain = "elastic.co"
        w = asyncwhois.lookup(test_domain)
        self.assertIn(f"domain name: {test_domain}", w.query_output.lower())
        self.assertEqual(w.parser_output.get('domain_name').lower(), test_domain)

    @mock.patch('asyncwhois.query.AsyncWhoIsQuery')
    async def test_aio_whois_cmd_shell(self, mock_query):
        mock_query_data = {'parser_output': {'domain_name': 'yahoo.com'}, 'query_output': 'Domain Name: yahoo.com'}
        mock_query._aio_from_whois_cmd.return_value = mock.Mock(data=mock_query_data)
        test_domain = "yahoo.com"
        w = await asyncwhois.aio_whois_cmd_shell(test_domain)
        self.assertIn(f"domain name: {test_domain}", w.query_output.lower())
        self.assertEqual(w.parser_output.get('domain_name').lower(), test_domain)

    @mock.patch('asyncwhois.query.WhoIsQuery')
    def test_whois_cmd_shell(self, mock_query):
        mock_query_data = {'parser_output': {'domain_name': 'comcast.net'}, 'query_output': 'Domain Name: comcast.net'}
        mock_query._from_whois_cmd.return_value = mock.Mock(data=mock_query_data)
        test_domain = "comcast.net"
        w = asyncwhois.whois_cmd_shell(test_domain)
        self.assertIn(f"domain name: {test_domain}", w.query_output.lower())
        self.assertEqual(w.parser_output.get('domain_name').lower(), test_domain)

    def test_has_parser_support(self):
        not_supported = 'zzz'
        self.assertFalse(asyncwhois.has_parser_support(not_supported))
        supported = 'com'
        self.assertTrue(asyncwhois.has_parser_support(supported))