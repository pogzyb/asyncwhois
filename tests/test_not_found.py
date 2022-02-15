import asynctest

import asyncwhois
from asyncwhois.errors import NotFoundError


class TestLookupNotFound(asynctest.TestCase):

    async def test_not_found_aio(self):
        domain = 'some-non-exsistent-domain123.com'
        self.assertAsyncRaises(NotFoundError, asyncwhois.aio_whois_domain(domain))

    def test_not_found(self):
        domain = 'some-non-exsistent-domain123.net'
        self.assertRaises(NotFoundError, asyncwhois.whois_domain, domain)
