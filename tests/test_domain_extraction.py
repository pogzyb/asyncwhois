from unittest import mock

import asyncwhois
from asyncwhois.client import DomainClient


def test_domain_client_uses_offline_tldextract_by_default():
    with mock.patch('asyncwhois.client.TLDExtract') as mock_tldextract:
        extractor = mock_tldextract.return_value
        registered_domain = 'google.co.uk'
        extractor.return_value = mock.Mock(
            registered_domain=registered_domain,
            suffix='uk',
        )

        client = DomainClient()
        full_domain, domain_core, suffix = client._get_domain_components(
            'https://www.google.co.uk/search?q=1'
        )

        mock_tldextract.assert_called_once_with(suffix_list_urls=())
        extractor.assert_called_once_with('https://www.google.co.uk/search?q=1')
        assert full_domain == registered_domain
        assert domain_core == 'google.co'
        assert suffix == 'uk'


def test_top_level_whois_accepts_preconfigured_tldextract():
    extractor = mock.Mock()

    with mock.patch('asyncwhois.DomainClient') as mock_domain_client:
        instance = mock_domain_client.return_value
        instance.whois.return_value = ('raw', {})

        asyncwhois.whois('https://www.google.com', tldextract_obj=extractor)

    assert mock_domain_client.call_args.kwargs['tldextract_obj'] is extractor
