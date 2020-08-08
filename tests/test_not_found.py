import asynctest

import asyncwhois
from asyncwhois.errors import WhoIsQueryParserError


class TestLookupNotFound(asynctest.TestCase):

    async def test_not_found_aio(self):
        domain = 'some-non-exsistent-domain123.com'
        self.assertAsyncRaises(WhoIsQueryParserError, await asyncwhois.aio_lookup(domain))

    def test_not_found(self):
        domain = 'some-non-exsistent-domain123.net'
        self.assertRaises(WhoIsQueryParserError, asyncwhois.lookup, domain)
