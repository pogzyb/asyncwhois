import asyncio
import sys
import unittest.mock as mock

import asyncwhois
from asyncwhois.servers import CountryCodeTLD
import pytest


test_domain_name = 'amazon.com'
mock_query_data = {
    'parser_output': {'domain_name': test_domain_name},
    'query_output': 'Domain Name: amazon.com'
}


if sys.version_info < (3, 8):
    @pytest.fixture()
    def mock_aio_whois_domain(mocker):
        future = asyncio.Future()
        future.set_result(mock.Mock(
            query_output=mock_query_data.get('query_output'),
            parser_output=mock_query_data.get('parser_output')
        ))
        mocker.patch('asyncwhois.pywhois.DomainLookup.aio_whois_domain', return_value=future)
        return future
else:
    @pytest.fixture()
    def mock_aio_whois_domain(mocker):
        async_mock = mock.AsyncMock(
            return_value=mock.Mock(
                query_output=mock_query_data.get('query_output'),
                parser_output=mock_query_data.get('parser_output')
            )
        )
        mocker.patch('asyncwhois.pywhois.DomainLookup.aio_whois_domain', side_effect=async_mock)
        return async_mock


@pytest.fixture()
def mock_whois_domain(mocker):
    mocker.patch(
        'asyncwhois.pywhois.DomainLookup.whois_domain',
        return_value=mock.Mock(
            query_output=mock_query_data.get('query_output'),
            parser_output=mock_query_data.get('parser_output')
        )
     )


@pytest.mark.asyncio
async def test_aio_lookup(mock_aio_whois_domain):
    result = await asyncwhois.aio_whois_domain(test_domain_name)
    assert f"domain name: {test_domain_name}" in result.query_output.lower(), \
        f"domain name: {test_domain_name} not in {result.query_output.lower()}"
    assert result.parser_output.get('domain_name').lower() == test_domain_name


def test_lookup(mock_whois_domain):
    result = asyncwhois.whois_domain(test_domain_name)
    assert f"domain name: {test_domain_name}" in result.query_output.lower(), \
        f"domain name: {test_domain_name} not in {result.query_output.lower()}"
    assert result.parser_output.get('domain_name').lower() == test_domain_name


def test_input_parameters_for_domain_query(mocker):
    spy = mocker.spy(asyncwhois.query.DomainQuery, 'new')
    mocker.patch(
        'asyncwhois.query.DomainQuery._do_query',
        return_value=mock_query_data.get('query_output')
    )

    test_subdomain_name = 'example.org.ua'

    _ = asyncwhois.whois_domain(test_subdomain_name)
    call_args = spy.call_args_list[0][0]
    assert call_args[0] == test_subdomain_name
    assert call_args[1] == CountryCodeTLD.UA
