import asynctest

import asyncwhois


class TestAsyncWhoIsQuery(asynctest.TestCase):

    async def test_aio_lookup(self):
        test_domain = "amazon.com"
        w = await asyncwhois.aio_lookup(test_domain)
        self.assertIn(f"domain name: {test_domain}", w.query_output.lower())
        self.assertEqual(w.parser_output.get('domain_name').lower(), test_domain)

    def test_lookup(self):
        test_domain = "elastic.co"
        w = asyncwhois.lookup(test_domain)
        self.assertIn(f"domain name: {test_domain}", w.query_output.lower())
        self.assertEqual(w.parser_output.get('domain_name').lower(), test_domain)

    async def test_aio_whois_cmd_shell(self):
        test_domain = "yahoo.com"
        w = await asyncwhois.aio_whois_cmd_shell(test_domain)
        self.assertIn(f"domain name: {test_domain}", w.query_output.lower())
        self.assertEqual(w.parser_output.get('domain_name').lower(), test_domain)

    def test_whois_cmd_shell(self):
        test_domain = "comcast.net"
        w = asyncwhois.whois_cmd_shell(test_domain)
        self.assertIn(f"domain name: {test_domain}", w.query_output.lower())
        self.assertEqual(w.parser_output.get('domain_name').lower(), test_domain)

    def test_has_parser_support(self):
        not_supported = 'zzz'
        self.assertFalse(asyncwhois.has_parser_support(not_supported))
        supported = 'com'
        self.assertTrue(asyncwhois.has_parser_support(supported))