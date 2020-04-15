import asyncio
from typing import Set
import re
import os

import aiodns
# import aiofiles

from .errors import DomainValidationError


# https://www.regextester.com/104038
IPV4_OR_V6 = re.compile(r"((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))")


# def cache(func):
#     """Save the list of TLDs"""
#     simple_cache = {}
#
#     async def reader(data):
#         if data not in simple_cache:
#             simple_cache[data] = await func(data)
#         return simple_cache[data]
#     return reader
#
#
# @cache
# async def load_suffixes(tld_file_path: str) -> Set[bytes]:
#     """Load the list of TLDs"""
#     suffixes = set()
#     async with aiofiles.open(tld_file_path, encoding='utf-8', mode='r') as f:
#         async for line in f:
#             if line and not line.startswith('//'):
#                 suffixes.add(line.rstrip('\n').encode('utf-8'))
#     return suffixes


def cache(func):
    """Cache the list of TLDs"""
    simple_cache = {}

    def reader(data):
        if data not in simple_cache:
            simple_cache[data] = func(data)
        return simple_cache[data]
    return reader


@cache
def load_suffixes(tld_file_path: str) -> Set[bytes]:
    """Load the list of TLDs"""
    suffixes = set()
    with open(tld_file_path, encoding='utf-8', mode='r') as f:
        for line in f.readlines():
            if line and not line.startswith('//'):
                suffixes.add(line.rstrip('\n').encode('utf-8'))
    return suffixes


async def extract_domain(url) -> str:
    """Extract the domain from the given URL"""
    if IPV4_OR_V6.match(url):
        loop = asyncio.get_event_loop()
        resolver = aiodns.DNSResolver(loop=loop)
        try:
            result = await resolver.gethostbyaddr(url)
            return result.name
        except aiodns.error.DNSError as e:
            raise DomainValidationError(e)

    # downloaded from https://publicsuffix.org/list/public_suffix_list.dat
    tlds_path = os.path.join(os.getcwd(), os.path.dirname(__file__), 'data', 'public_suffix_list.dat')
    # suffixes = await load_suffixes(tlds_path)
    suffixes = load_suffixes(tlds_path)

    if not isinstance(url, str):
        url = url.decode('utf-8')
    url = re.sub('^.*://', '', url)
    url = url.split('/')[0].lower()

    # find the longest suffix match
    domain = b''
    for section in reversed(url.split('.')):
        if domain:
            domain = b'.' + domain
        domain = section.encode('utf-8') + domain
        if domain not in suffixes:
            break
    return domain.decode('utf-8')
