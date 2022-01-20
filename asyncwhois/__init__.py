from typing import Any, Optional

from .pywhois import PyWhoIs


__all__ = [
    'lookup',
    'aio_lookup',
    'whois_cmd_shell',
    'aio_whois_cmd_shell',
    'rdap_domain_lookup',
    'aio_rdap_domain_lookup'
]
__version__ = '0.4.1'


def lookup(url: str, timeout: int = 10) -> PyWhoIs:
    """
    Module entry point for whois lookups. Opens a socket connection to the
    whois server, submits a query, and then parses the query output from the server
    into a dictionary. Uses "socket.create_connection()" for the socket.
    Raises "QueryError" if connection to a server times out or fails.
    Raises "NotFoundError" if domain record is "not found" on the server.

    :param url: Any correctly formatted URL (e.g. https://en.wikipedia.org/wiki/WHOIS)
    :param timeout: whois server connection timeout (default 10 seconds)
    :return: instance of PyWhoIs with "query_output" and "parser_output" attributes
    """
    whois = PyWhoIs._from_url(url, timeout)
    return whois


def whois_cmd_shell(url: str, timeout: int = 10) -> PyWhoIs:
    """
    Equivalent to running "whois <domain>" from the shell. Uses subprocess.Popen().

    :param url: Any correctly formatted URL (e.g. https://en.wikipedia.org/wiki/WHOIS)
    :param timeout: whois server connection timeout (default 10 seconds)
    :return: instance of PyWhoIs with "query_output" and "parser_output" attributes
    """
    whois = PyWhoIs._from_whois_cmd(url, timeout)
    return whois


async def aio_lookup(url: str, timeout: int = 10) -> PyWhoIs:
    """
    Asynchronous module entry point for whois lookups. Opens a socket connection to the
    whois server, submits a query, and then parses the query output from the server
    into a dictionary. Uses "asyncio.open_connection()" for the socket.
    Raises "QueryError" if connection to a server times out or fails.
    Raises "NotFoundError" if domain record is "not found" on the server.

    :param url: Any correctly formatted URL (e.g. https://en.wikipedia.org/wiki/WHOIS)
    :param timeout: whois server connection timeout (default 10 seconds)
    :return: instance of PyWhoIs with "query_output" and "parser_output" attributes
    """
    whois = await PyWhoIs._aio_from_url(url, timeout)
    return whois


def rdap_domain_lookup(url: str, http_client: Optional[Any] = None) -> PyWhoIs:
    """
    Runs an RDAP query for the given url.

    :param url: Any correctly formatted URL (e.g. https://en.wikipedia.org/wiki/WHOIS)
    :param http_client: Optional HTTP Client such as `httpx.Client` or `requests.Session`
    :return: instance of PyWhoIs with "query_output" and "parser_output" attributes
    """
    whois = PyWhoIs._rdap_domain_from_url(url, http_client)
    return whois


async def aio_rdap_domain_lookup(url: str, http_client: Optional[Any] = None) -> PyWhoIs:
    """
    Runs an RDAP query for the given url.

    :param url: Any correctly formatted URL (e.g. https://en.wikipedia.org/wiki/WHOIS)
    :param http_client: Optional Async HTTP Client such as `httpx.AsyncClient`
    :return: instance of PyWhoIs with "query_output" and "parser_output" attributes
    """
    whois = await PyWhoIs._aio_rdap_domain_from_url(url, http_client)
    return whois


async def aio_whois_cmd_shell(url: str, timeout: int = 10) -> PyWhoIs:
    """
    Equivalent to running "whois <domain>" from the shell. Leverages "asyncio.subprocess".
    IMPORTANT: Raises "NotImplementedError" if running on Windows and the event loop is
    not set to be type "asyncio.ProactorEventLoop". Must set: loop = asyncio.ProactorEventLoop()

    :param url: Any correctly formatted URL (e.g. https://en.wikipedia.org/wiki/WHOIS)
    :param timeout: whois server connection timeout (default 10 seconds)
    :return: instance of PyWhoIs with "query_output" and "parser_output" attributes
    """
    whois = await PyWhoIs._aio_from_whois_cmd(url, timeout)
    return whois

