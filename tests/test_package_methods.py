import asynctest
import unittest.mock as mock
import asynctest.mock as aio_mock

import asyncwhois


class TestExportedFunctions(asynctest.TestCase):

    @aio_mock.patch('asyncwhois.pywhois.DomainLookup.aio_whois_domain')
    async def test_aio_lookup(self, mock_whois_call):
        mock_query_data = {'parser_output': {'domain_name': 'amazon.com'}, 'query_output': 'Domain Name: amazon.com'}
        mock_whois_call.return_value = mock.Mock(query_output=mock_query_data.get('query_output'),
                                                 parser_output=mock_query_data.get('parser_output'))
        test_domain = "amazon.com"
        w = await asyncwhois.aio_whois_domain(test_domain)
        mock_whois_call.assert_called_once()
        self.assertIn(f"domain name: {test_domain}", w.query_output.lower())
        self.assertEqual(w.parser_output.get('domain_name').lower(), test_domain)

    @mock.patch('asyncwhois.pywhois.DomainLookup.whois_domain')
    def test_lookup(self, mock_whois_call):
        mock_query_data = {'parser_output': {'domain_name': 'elastic.co'}, 'query_output': 'Domain Name: elastic.co'}
        mock_whois_call.return_value = mock.Mock(query_output=mock_query_data.get('query_output'),
                                                 parser_output=mock_query_data.get('parser_output'))
        test_domain = "elastic.co"
        w = asyncwhois.whois_domain(test_domain)
        mock_whois_call.assert_called_once()
        self.assertIn(f"domain name: {test_domain}", w.query_output.lower())
        self.assertEqual(w.parser_output.get('domain_name').lower(), test_domain)

