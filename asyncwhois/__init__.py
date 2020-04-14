import logging

from .parser import WhoisEntry
from .query import do_async_whois_query
from .utils import extract_domain
from .tlds import fully_supported_tlds

logger = logging.getLogger("asyncwhois")


async def lookup(url: str) -> WhoisEntry:
    """
    Entrypoint for asyncwhois queries

    :param url: the url to do the WhoIs lookup on
    :return: instance of dict-like WhoisEntry
    """
    domain = await extract_domain(url)
    query_result = await do_async_whois_query(domain)
    return WhoisEntry.load(domain, query_result)


def has_support_for(tld: str) -> bool:
    """
    Check if asyncwhois explicitly supports the given TLD
    **Note: by default, an error is NOT raised if the module does
    not support parsing WhoIs output for any TLD. The parser
    will attempt to extract information regardless.

    :param tld: top level domain (.com, .net, .online, etc..)
    :return: True if explicit parser support else False
    """
    return tld in fully_supported_tlds
