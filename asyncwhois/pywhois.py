import asyncio
import re
import socket
import subprocess
import sys
from typing import Union, Dict, Any

import aiodns
import tldextract

from .errors import QueryError
from .parser import WhoIsParser
from .query import WhoIsQuery, AsyncWhoIsQuery
from .servers import CountryCodeTLD, GenericTLD, SponsoredTLD

# https://www.regextester.com/104038
IPV4_OR_V6 = re.compile(
    r"((^\s*((([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5]))\s*$)|(^\s*((([0-9A-Fa-f]{1,4}:){7}([0-9A-Fa-f]{1,4}|:))|(([0-9A-Fa-f]{1,4}:){6}(:[0-9A-Fa-f]{1,4}|((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){5}(((:[0-9A-Fa-f]{1,4}){1,2})|:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3})|:))|(([0-9A-Fa-f]{1,4}:){4}(((:[0-9A-Fa-f]{1,4}){1,3})|((:[0-9A-Fa-f]{1,4})?:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){3}(((:[0-9A-Fa-f]{1,4}){1,4})|((:[0-9A-Fa-f]{1,4}){0,2}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){2}(((:[0-9A-Fa-f]{1,4}){1,5})|((:[0-9A-Fa-f]{1,4}){0,3}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(([0-9A-Fa-f]{1,4}:){1}(((:[0-9A-Fa-f]{1,4}){1,6})|((:[0-9A-Fa-f]{1,4}){0,4}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:))|(:(((:[0-9A-Fa-f]{1,4}){1,7})|((:[0-9A-Fa-f]{1,4}){0,5}:((25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}))|:)))(%.+)?\s*$))")


class PyWhoIs:

    def __init__(self):
        self.__query = None
        self.__parser = None

    @staticmethod
    def _get_server_name(tld: str) -> Union[str, None]:
        tld_converted = tld.upper().replace('-', '_')
        for servers in [CountryCodeTLD, GenericTLD, SponsoredTLD]:
            if hasattr(servers, tld_converted):
                server = getattr(servers, tld_converted)
                return server
        return None

    @staticmethod
    def _get_tld_extract(url: str) -> tldextract.tldextract.ExtractResult:
        extract_result = tldextract.extract(url)
        return extract_result

    @staticmethod
    def _get_hostname_from_ip(ip_address: str) -> Union[str, None]:
        try:
            host, _, _ = socket.gethostbyaddr(ip_address)
            return host
        except socket.herror:
            raise QueryError(f'Could not resolve {ip_address}')

    @staticmethod
    async def _aio_get_hostname_from_ip(ip_address: str) -> Union[str, None]:
        loop = asyncio.get_event_loop()
        resolver = aiodns.DNSResolver(loop=loop)
        try:
            host = await resolver.gethostbyaddr(ip_address)
            return host.name
        except aiodns.error.DNSError:
            raise QueryError(f'Could not resolve {ip_address}')

    @property
    def parser_output(self) -> Dict[str, Any]:
        return self.__parser.parser_output

    @property
    def query_output(self) -> str:
        if isinstance(self.__query, (WhoIsQuery, AsyncWhoIsQuery)):
            return self.__query.query_output
        else:
            return self.__query

    @classmethod
    def _from_whois_cmd(cls, url: str, timeout: int):
        pywhois = cls()
        extract_result = tldextract.extract(url)

        if IPV4_OR_V6.match(extract_result.domain):
            host = pywhois._get_hostname_from_ip(extract_result.domain)
            extract_result = tldextract.extract(host)

        tld = extract_result.suffix
        if len(tld.split('.')) > 1:
            tld = tld.split('.')[-1]

        domain_and_tld = extract_result.domain + '.' + tld
        # open new process for "whois" command
        proc = subprocess.Popen(
            ["whois", f"{domain_and_tld}"],
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        parser = WhoIsParser(tld)
        try:
            # block for query_result
            query_result, _ = proc.communicate(timeout=timeout)
            query_result = query_result.decode(errors='ignore')
        except subprocess.TimeoutExpired:
            raise QueryError(
                f'The shell command "whois {domain_and_tld}" exceeded timeout of {timeout} seconds')
        parser.parse(query_result)
        pywhois.__query = query_result
        pywhois.__parser = parser
        return pywhois

    @classmethod
    def _from_url(cls, url: str, timeout: int):
        pywhois = cls()
        extract_result = tldextract.extract(url)

        if IPV4_OR_V6.match(extract_result.domain):
            host = pywhois._get_hostname_from_ip(extract_result.domain)
            extract_result = tldextract.extract(host)

        tld = extract_result.suffix
        if len(tld.split('.')) > 1:
            tld = tld.split('.')[-1]

        domain_and_tld = extract_result.domain + '.' + tld
        parser = WhoIsParser(tld)
        server = cls._get_server_name(tld)
        query = WhoIsQuery(domain_and_tld, server, timeout)
        parser.parse(query.query_output)
        pywhois.__query = query
        pywhois.__parser = parser
        return pywhois

    @classmethod
    async def _aio_from_whois_cmd(cls, url: str, timeout: int):
        # On Windows the asyncio loop must be set to "ProactorEventLoop" in order to use asyncio subprocess
        # Note: Changed in [Python] version 3.8: On Windows, ProactorEventLoop is now used by default.
        # https://docs.python.org/3/library/asyncio-platforms.html#subprocess-support-on-windows
        if sys.platform in ("windows", "win32") and not isinstance(asyncio.get_running_loop(),
                                                                   asyncio.ProactorEventLoop):
            loop_error_message = "You must set the running loop to 'asyncio.ProactorEventLoop' in order to use an asyncio subprocess on Windows."
            raise NotImplementedError(loop_error_message)

        pywhois = cls()
        extract_result = tldextract.extract(url)

        if IPV4_OR_V6.match(extract_result.domain):
            host = pywhois._get_hostname_from_ip(extract_result.domain)
            extract_result = tldextract.extract(host)

        tld = extract_result.suffix
        if len(tld.split('.')) > 1:
            tld = tld.split('.')[-1]

        domain_and_tld = extract_result.domain + '.' + tld
        # open a new process for "whois" command
        proc = await asyncio.create_subprocess_shell(
            f"whois {domain_and_tld}",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        parser = WhoIsParser(tld)
        try:
            # block for query_result
            query_result, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            query_result = query_result.decode(errors='ignore')
        except asyncio.TimeoutError:
            raise QueryError(
                f'The shell command "whois {domain_and_tld}" exceeded timeout of {timeout} seconds')
        parser.parse(query_result)
        pywhois.__query = query_result
        pywhois.__parser = parser
        return pywhois

    @classmethod
    async def _aio_from_url(cls, url: str, timeout: int):
        pywhois = cls()
        extract_result = tldextract.extract(url)

        if IPV4_OR_V6.match(extract_result.domain):
            host = await pywhois._aio_get_hostname_from_ip(extract_result.domain)
            extract_result = tldextract.extract(host)

        tld = extract_result.suffix
        if len(tld.split('.')) > 1:
            tld = tld.split('.')[-1]

        domain_and_tld = extract_result.domain + '.' + tld
        server = cls._get_server_name(tld)
        query = await AsyncWhoIsQuery.create(domain_and_tld, server, timeout)
        parser = WhoIsParser(tld)
        parser.parse(query.query_output)
        pywhois.__query = query
        pywhois.__parser = parser
        return pywhois
