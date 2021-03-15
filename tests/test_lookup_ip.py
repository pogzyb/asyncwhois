import asynctest
import unittest.mock as mock

import asyncwhois


class TestIPSupport(asynctest.TestCase):

    def test_pywhois_get_hostname_from_ip(self):
        pyw = asyncwhois.PyWhoIs()
        host = pyw._get_hostname_from_ip('8.8.8.8')
        self.assertEqual(host, 'dns.google', 'Failed to resolve: 8.8.8.8 to dns.google')

    async def test_pywhois_aio_get_hostname_from_ip(self):
        pyw = asyncwhois.PyWhoIs()
        host = await pyw._aio_get_hostname_from_ip('8.8.8.8')
        self.assertEqual(host, 'dns.google', 'Failed to resolve: 8.8.8.8 to dns.google')

    @mock.patch('asyncwhois.pywhois.PyWhoIs._from_url')
    def test_pywhois_lookup_on_ipv4(self, mock_whois_call):
        mock_query_data = {'parser_output': {'domain_name': '1e100.net'}, 'query_output': 'Domain Name: 1e100.net'}
        mock_whois_call.return_value = mock.Mock(query_output=mock_query_data.get('query_output'),
                                                 parser_output=mock_query_data.get('parser_output'))
        result = asyncwhois.lookup('172.217.3.110')
        self.assertIn("domain name: 1e100.net", result.query_output.lower())

    @mock.patch('asyncwhois.pywhois.PyWhoIs._aio_from_url')
    async def test_pywhois_aio_lookup_ipv4(self, mock_whois_call):
        mock_query_data = {'parser_output': {'domain_name': 'dns.google'}, 'query_output': 'Domain Name: dns.google'}
        mock_whois_call.return_value = mock.Mock(query_output=mock_query_data.get('query_output'),
                                                 parser_output=mock_query_data.get('parser_output'))
        result = await asyncwhois.aio_lookup('8.8.8.8')
        self.assertIn("domain name: dns.google", result.query_output.lower())
