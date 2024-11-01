import sys

import pytest
import asyncwhois
from asyncwhois.errors import NotFoundError

if sys.version_info >= (3, 8):
    from unittest import IsolatedAsyncioTestCase

    class TestLookupNotFound(IsolatedAsyncioTestCase):
        @pytest.mark.skip(reason="this is failing on github actions")
        async def test_not_found_aio(self):
            domain = "some-non-existent-domain123.com"
            with self.assertRaises(NotFoundError):
                await asyncwhois.aio_whois(domain)

        @pytest.mark.skip(reason="this is failing on github actions")
        def test_not_found(self):
            domain = "some-non-existent-domain123.com"
            with self.assertRaises(NotFoundError):
                asyncwhois.whois(domain)

            asyncwhois.whois(domain, ignore_not_found=True)
