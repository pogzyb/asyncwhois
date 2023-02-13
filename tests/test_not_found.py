import sys

import asyncwhois
from asyncwhois.errors import NotFoundError

if sys.version_info >= (3, 8):
    from unittest import IsolatedAsyncioTestCase

    class TestLookupNotFound(IsolatedAsyncioTestCase):

        async def test_not_found_aio(self):
            domain = 'some-non-existent-domain123.com'
            with self.assertRaises(NotFoundError):
                await asyncwhois.aio_whois_domain(domain)

        def test_not_found(self):
            domain = 'some-non-existent-domain123.com'
            with self.assertRaises(NotFoundError):
                asyncwhois.whois_domain(domain)
