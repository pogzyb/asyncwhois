import asyncio
import socket
import sys
import unittest.mock as mock
from types import SimpleNamespace

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


class DummyExtract:
    def __call__(self, domain):
        suffix = domain.split(".")[-1]
        return SimpleNamespace(registered_domain=domain, suffix=suffix)

# TODO: work-in-progess on default fallback to RDAP if WHOIS fails
# def test_domain_whois_falls_back_to_rdap_on_gaierror(mocker):
#     client = asyncwhois.DomainClient(tldextract_obj=DummyExtract())
#     mocker.patch.object(
#         client.query_obj,
#         "run",
#         side_effect=socket.gaierror(8, "nodename nor servname provided, or not known"),
#     )
#     fallback = ('{"fallback":"rdap"}', {"domain_name": "my-relay.app"})
#     rdap_mock = mocker.patch.object(client, "rdap", return_value=fallback)

#     assert client.whois("my-relay.app") == fallback
#     rdap_mock.assert_called_once_with("my-relay.app")


# @pytest.mark.asyncio
# async def test_domain_aio_whois_falls_back_to_rdap_on_gaierror(mocker):
#     client = asyncwhois.DomainClient(tldextract_obj=DummyExtract())
#     mocker.patch.object(
#         client.query_obj,
#         "aio_run",
#         side_effect=socket.gaierror(8, "nodename nor servname provided, or not known"),
#     )
#     fallback = ('{"fallback":"rdap"}', {"domain_name": "my-relay.app"})
#     rdap_mock = mocker.patch.object(client, "aio_rdap", new=mock.AsyncMock(return_value=fallback))

#     assert await client.aio_whois("my-relay.app") == fallback
#     rdap_mock.assert_awaited_once_with("my-relay.app")
