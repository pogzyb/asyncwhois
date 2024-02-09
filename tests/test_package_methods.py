import asyncio
import sys
import unittest.mock as mock

import asyncwhois
import pytest


test_domain_name = "amazon.com"
mock_response = ("Domain Name: amazon.com", {"domain_name": test_domain_name})


if sys.version_info < (3, 8):

    @pytest.fixture()
    def mock_aio_whois_domain(mocker):
        future = asyncio.Future()
        future.set_result(mock_response)
        mocker.patch("asyncwhois.client.DomainClient.aio_whois", return_value=future)
        return future

else:

    @pytest.fixture()
    def mock_aio_whois_domain(mocker):
        async_mock = mock.AsyncMock(return_value=mock_response)
        mocker.patch("asyncwhois.client.DomainClient.aio_whois", side_effect=async_mock)
        return async_mock


@pytest.fixture()
def mock_whois_domain(mocker):
    mocker.patch(
        "asyncwhois.client.DomainClient.whois",
        return_value=mock_response,
    )


@pytest.mark.asyncio
async def test_aio_whois(mock_aio_whois_domain):
    q, p = await asyncwhois.aio_whois(test_domain_name)
    assert (
        f"domain name: {test_domain_name}" in q.lower()
    ), f"domain name: {test_domain_name} not in {q.lower()}"
    assert p.get("domain_name").lower() == test_domain_name


def test_whois(mock_whois_domain):
    q, p = asyncwhois.whois(test_domain_name)
    assert (
        f"domain name: {test_domain_name}" in q.lower()
    ), f"domain name: {test_domain_name} not in {q.lower()}"
    assert p.get("domain_name").lower() == test_domain_name
