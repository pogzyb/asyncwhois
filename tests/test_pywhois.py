import unittest

from asyncwhois.pywhois import DomainLookup


class TestDomainLookup(unittest.TestCase):

    def setUp(self) -> None:
        self.fake_domain = "some-domain-somewhere-out-there.co.uk"
        self.fake_query_result = "Domain Name: some-domain-somewhere-out-there.co.uk"

    def test__get_server_name(self):
        pyw = DomainLookup()
        generic_tld = 'com'
        whois_server = pyw._get_server_name(generic_tld)
        self.assertEqual(whois_server, 'whois.verisign-grs.com')
        generic_tld_unicode = 'xn--4gbrim'
        whois_server = pyw._get_server_name(generic_tld_unicode)
        self.assertEqual(whois_server, 'whois.afilias-srs.net')
        country_tld = 'us'
        whois_server = pyw._get_server_name(country_tld)
        self.assertEqual(whois_server, 'whois.nic.us')
        sponsored_tld = 'aero'
        whois_server = pyw._get_server_name(sponsored_tld)
        self.assertEqual(whois_server, 'whois.aero')

    def test__get_top_level_domain(self):
        pyw = DomainLookup()
        assert pyw._get_top_level_domain('https://www.google.co.uk') == 'uk'
        assert pyw._get_top_level_domain('https://www.wikipedia.org') == 'org'
        assert pyw._get_top_level_domain('https://www.coral.ai') == 'ai'
