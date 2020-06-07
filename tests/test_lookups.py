import asynctest

import asyncwhois


class TestLookup(asynctest.TestCase):

    def test_lookup_ipv4(self):
        result = asyncwhois.lookup('172.217.3.110')
        self.assertIn("domain name: 1e100.net\n", result.query_output.lower())
