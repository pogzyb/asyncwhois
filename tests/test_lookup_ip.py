import asynctest

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

    def test_pywhois_lookup_on_ipv4(self):
        result = asyncwhois.lookup('172.217.3.110')
        self.assertIn("domain name: 1e100.net", result.query_output.lower())

    async def test_pywhois_aio_lookup_ipv4(self):
        result = await asyncwhois.aio_lookup('8.8.8.8')
        self.assertIn("domain name: dns.google", result.query_output.lower())
