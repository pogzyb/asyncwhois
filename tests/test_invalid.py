import asynctest

import asyncwhois
from asyncwhois.errors import WhoIsQueryError


class TestInvalidLookup(asynctest.TestCase):

    async def test_invalid_aio(self):
        domain = 'some-non-exsistent-domain123.com'
        self.assertAsyncRaises(WhoIsQueryError, asyncwhois.aio_lookup(domain))

    def test_invalid(self):
        domain = 'some-non-exsistent-domain123.net'
        self.assertRaises(WhoIsQueryError, asyncwhois.lookup, domain)
