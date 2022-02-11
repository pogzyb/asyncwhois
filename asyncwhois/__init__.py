from ipaddress import IPv4Address, IPv6Address
from typing import Any, Optional, Union

from .pywhois import DomainLookup, NumberLookup, ASNLookup

__all__ = [
    'aio_whois_domain',
    'aio_whois_ipv4',
    'aio_whois_ipv6',
    'aio_rdap_domain',
    'aio_rdap_ipv4',
    'aio_rdap_ipv6',
    'aio_rdap_asn',
    'rdap_domain',
    'rdap_ipv4',
    'rdap_ipv6',
    'rdap_asn',
    'whois_domain',
    'whois_ipv4',
    'whois_ipv6',
]
__version__ = '1.0.0'


def whois_domain(
    domain: str,
    authoritative_only: bool = False,
    proxy_url: str = None,
    timeout: int = 10
) -> DomainLookup:
    """
    Performs domain lookups with WHOIS.
    Finds the authoritative WHOIS server and parses the response from the server.

    :param domain: Any domain or URL (e.g. 'wikipedia.org' or 'https://en.wikipedia.org/wiki/WHOIS')
    :param authoritative_only: If False, returns the entire WHOIS query chain
        in `query_output`; If True only the authoritative response is included.
    :param proxy_url: Optional SOCKS4 or SOCKS5 proxy url (e.g. 'socks5://host:port')
    :param timeout: Connection timeout. Default is 10 seconds.
    :return: instance of DomainLookup
    """
    result = DomainLookup.whois_domain(domain, authoritative_only, proxy_url, timeout)
    return result


async def aio_whois_domain(
    domain: str,
    authoritative_only: bool = False,
    proxy_url: str = None,
    timeout: int = 10
) -> DomainLookup:
    """
    Performs asynchronous domain lookups with WHOIS.
    Finds the authoritative WHOIS server and parses the response from the server.

    :param domain: Any domain or URL (e.g. 'wikipedia.org' or 'https://en.wikipedia.org/wiki/WHOIS')
    :param authoritative_only: If False, returns the entire WHOIS query chain
        in `query_output`; If True only the authoritative response is included.
    :param proxy_url: Optional SOCKS4 or SOCKS5 proxy url (e.g. 'socks5://host:port')
    :param timeout: Connection timeout. Default is 10 seconds.
    :return: instance of DomainLookup
    """
    result = await DomainLookup.aio_whois_domain(domain, authoritative_only,
                                                  proxy_url, timeout)
    return result


def rdap_domain(
    domain: str,
    httpx_client: Optional[Any] = None
) -> DomainLookup:
    """
    Performs an RDAP query for the given domain.
    Finds the authoritative RDAP server and parses the response from that server.

    :param domain: Any domain name or URL
        (e.g. 'wikipedia.org' or 'https://en.wikipedia.org/wiki/WHOIS')
    :param httpx_client: Optional preconfigured `httpx.Client`
    :return: instance of DomainLookup
    """
    result = DomainLookup.rdap_domain(domain, httpx_client)
    return result


async def aio_rdap_domain(
    domain: str,
    httpx_client: Optional[Any] = None
) -> DomainLookup:
    """
    Performs an async RDAP query for the given domain name.

    :param domain: Any domain or URL (e.g. 'wikipedia.org' or 'https://en.wikipedia.org/wiki/WHOIS')
    :param httpx_client: Optional preconfigured `httpx.AsyncClient`
    :return: instance of DomainLookup
    """
    result = await DomainLookup.aio_rdap_domain(domain, httpx_client)
    return result


def whois_ipv4(
    ipv4: Union[IPv4Address, str],
    authoritative_only: bool = False,
    proxy_url: str = None,
    timeout: int = 10
) -> NumberLookup:
    """
    Performs a WHOIS query for the given IPv4 address.
    Finds the authoritative WHOIS server and parses the response from the server.

    :param ipv4: ip address as a str or `ipaddress.IPv4Address` object
    :param authoritative_only: If False, returns the entire WHOIS query chain
        in `query_output`; If True only the authoritative response is included.
    :param proxy_url: Optional SOCKS4 or SOCKS5 proxy url
    :param timeout: Connection timeout. Default is 10 seconds.
    :return: instance of DomainLookup
    """
    result = NumberLookup.whois_ipv4(ipv4, authoritative_only, proxy_url, timeout)
    return result


async def aio_whois_ipv4(
    ipv4: Union[IPv4Address, str],
    authoritative_only: bool = False,
    proxy_url: str = None,
    timeout: int = 10
) -> NumberLookup:
    """
    Performs an async WHOIS query for the given IPv4 address.
    Finds the authoritative WHOIS server and parses the response from the server.

    :param ipv4: ip address as a str or `ipaddress.IPv4Address` object
    :param authoritative_only: If False, returns the entire WHOIS query chain
        in `query_output`; If True only the authoritative response is included.
    :param proxy_url: Optional SOCKS4 or SOCKS5 proxy url
    :param timeout: Connection timeout. Default is 10 seconds.
    :return: instance of NumberLookup
    """
    result = await NumberLookup.aio_whois_ipv4(ipv4, authoritative_only, proxy_url, timeout)
    return result


def rdap_ipv4(
    ipv4: Union[IPv4Address, str],
    httpx_client: Optional[Any] = None
) -> NumberLookup:
    """
    Performs an RDAP query for the given IPv4 address.

    :param ipv4: IP address as a string or `ipaddress.IPv4Address` object
    :param httpx_client: Optional preconfigured `httpx.Client`
    :return: instance of NumberLookup
    """
    result = NumberLookup.rdap_ipv4(ipv4, httpx_client)
    return result


async def aio_rdap_ipv4(
    ipv4: Union[IPv4Address, str],
    httpx_client: Optional[Any] = None
) -> NumberLookup:
    """
    Performs an async RDAP query for the given IPv6 address.

    :param ipv4: IP address as a string or `ipaddress.IPv4Address` object
    :param httpx_client: Optional preconfigured `httpx.AsyncClient`
    :return: instance of NumberLookup
    """
    result = await NumberLookup.aio_rdap_ipv4(ipv4, httpx_client)
    return result


def whois_ipv6(
    ipv6: Union[IPv6Address, str],
    authoritative_only: bool = False,
    proxy_url: str = None,
    timeout: int = 10
) -> NumberLookup:
    """
    Performs a WHOIS query for the given IPv6 address.
    Looks up the WHOIS server, submits the query, and then parses the response from the server.

    :param ipv6: ip address as a str or `ipaddress.IPv6address` object
    :param authoritative_only: If False, returns the entire WHOIS query chain
        in `query_output`; If True only the authoritative response is included.
    :param proxy_url: Optional SOCKS4 or SOCKS5 proxy url
    :param timeout: Connection timeout. Default is 10 seconds.
    :return: instance of NumberLookup
    """
    result = NumberLookup.whois_ipv6(ipv6, authoritative_only, proxy_url, timeout)
    return result


async def aio_whois_ipv6(
    ipv6: Union[IPv6Address, str],
    authoritative_only: bool = False,
    proxy_url: str = None,
    timeout: int = 10
) -> NumberLookup:
    """
    Performs an async WHOIS query for the given IPv6 address.
    Looks up the WHOIS server, submits the query, and then parses the response from the server.

    :param ipv6: ip address as a str or `ipaddress.IPv6Address` object
    :param authoritative_only: If False, returns the entire WHOIS query chain
        in `query_output`; If True only the authoritative response is included.
    :param proxy_url: Optional SOCKS4 or SOCKS5 proxy url
    :param timeout: Connection timeout. Default is 10 seconds.
    :return: instance of NumberLookup
    """
    result = await NumberLookup.aio_whois_ipv6(ipv6, authoritative_only, proxy_url, timeout)
    return result


def rdap_ipv6(
    ipv6: Union[IPv6Address, str],
    httpx_client: Optional[Any] = None
) -> NumberLookup:
    """
    Performs an RDAP query for the given IPv6 address.

    :param ipv6: IP address as a string or `ipaddress.IPv6Address` object
    :param httpx_client: Optional preconfigured `httpx.Client`
    :return: instance of NumberLookup
    """
    result = NumberLookup.rdap_ipv6(ipv6, httpx_client)
    return result


async def aio_rdap_ipv6(
    ipv6: Union[IPv6Address, str],
    httpx_client: Optional[Any] = None
) -> NumberLookup:
    """
    Performs an async RDAP query for the given IPv6 address.

    :param ipv6: IP address as a string or `ipaddress.IPv6Address` object
    :param httpx_client: Optional preconfigured `httpx.AsyncClient`
    :return: instance of NumberLookup
    """
    result = await NumberLookup.aio_rdap_ipv6(ipv6, httpx_client)
    return result


def rdap_asn(
    asn: int,
    httpx_client: Optional[Any] = None
) -> ASNLookup:
    """
    Performs an RDAP query for the given Autonomous System Number.

    :param asn: The ASN number as an integer
    :param httpx_client: Optional preconfigured `httpx.Client`
    :return: instance of ASNLookup
    """
    result = ASNLookup.rdap_asn(asn, httpx_client)
    return result


async def aio_rdap_asn(
    asn: int,
    httpx_client: Optional[Any] = None
) -> ASNLookup:
    """
    Performs an async RDAP query for the given Autonomous System Number.

    :param asn: The ASN number as an integer
    :param httpx_client: Optional preconfigured `httpx.AsyncClient`
    :return: instance of ASNLookup
    """
    result = await ASNLookup.aio_rdap_asn(asn, httpx_client)
    return result
