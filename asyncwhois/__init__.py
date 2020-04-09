import logging
import asyncio
import aiodns
import re
import os

from .parser import WhoisEntry
from .query import do_async_whois_query
from .utils import extract_domain

logger = logging.getLogger("asyncwhois")
logger.setLevel(logging.DEBUG)


async def lookup(url: str) -> WhoisEntry:
    domain = await extract_domain(url)
    query_result = await do_async_whois_query(domain)
    return WhoisEntry.load(domain, query_result)
