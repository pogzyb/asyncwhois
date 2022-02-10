import ipaddress
from typing import Union, Dict, Any, Optional

import tldextract
import whodap

from .parse_rir import NumberParser
from .parse_tld import DomainParser, TLDBaseKeys
from .query import DomainQuery, NumberQuery
from .servers import CountryCodeTLD, GenericTLD, SponsoredTLD, IPv4Allocations


class Lookup:

    def __init__(self):
        self._query = None
        self._parser = None

    @property
    def parser_output(self) -> Dict[str, Any]:
        if isinstance(self._parser, dict):
            return self._parser
        elif isinstance(self._parser, (DomainParser, NumberParser)):
            return self._parser.parser_output

    @property
    def query_output(self) -> str:
        if isinstance(self._query, (DomainQuery, NumberQuery)):
            if not self._query.authoritative_only:
                # return entire query chain
                return self._query.query_chain
            else:
                # return only the authoritative response
                return self._query.query_output
        else:
            return self._query


class DomainLookup(Lookup):

    def __init__(self):
        super().__init__()
        self._tld_extract = None

    @staticmethod
    def _get_server_name(tld: str) -> Union[str, None]:
        tld_converted = tld.upper().replace('-', '_')
        for servers in [CountryCodeTLD, GenericTLD, SponsoredTLD]:
            if hasattr(servers, tld_converted):
                server = getattr(servers, tld_converted)
                return server
        return None 
    
    def _get_top_level_domain(self, domain: str):
        self._tld_extract = tldextract.extract(domain)
        top_level_domain = self._tld_extract.suffix
        if '.' in top_level_domain:
            top_level_domain = top_level_domain.split('.')[-1]
        return top_level_domain
        
    @property
    def tld_extract_result(self) -> tldextract.tldextract.ExtractResult:
        return self._tld_extract

    @classmethod
    def whois_domain(
        cls,
        domain: str,
        authoritative_only: bool,
        proxy_url: str,
        timeout: int
    ):
        _self = cls()
        # get TLD
        top_level_domain = _self._get_top_level_domain(domain)
        # initialize parser based on given TLD
        parser = DomainParser(top_level_domain)
        # get the WHOIS server associated with this TLD
        server = _self._get_server_name(top_level_domain)
        # submit the WHOIS query to the server
        hostname = _self.tld_extract_result.domain + '.' + top_level_domain
        query = DomainQuery.new(hostname, server, authoritative_only, proxy_url, timeout)
        # parse the raw text output from the WHOIS server
        parser.parse(query.query_output)
        _self._query = query
        _self._parser = parser
        return _self

    @classmethod
    async def aio_whois_domain(
        cls,
        domain: str,
        authoritative_only: bool,
        proxy_url: str,
        timeout: int
    ):
        _self = cls()
        # get TLD
        top_level_domain = _self._get_top_level_domain(domain)
        # initialize parser based on given TLD
        parser = DomainParser(top_level_domain)
        # get the WHOIS server associated with this TLD
        server = _self._get_server_name(top_level_domain)
        # submit the WHOIS query to the server
        hostname = _self.tld_extract_result.domain + '.' + top_level_domain
        query = await DomainQuery.new_aio(hostname, server, authoritative_only, proxy_url, timeout)
        # parse the raw text output from the WHOIS server
        parser.parse(query.query_output)
        _self._query = query
        _self._parser = parser
        return _self

    @classmethod
    def rdap_domain(
        cls,
        domain: str,
        httpx_client: Any = None
    ):
        """
        Performs an RDAP query using the `whodap` project.
        Stores the resulting RDAP output into "query_output" and a WHOIS friendly
        key:value pair dictionary into "parser_output".

        :param domain: the domain or URL to search (e.g. 'google.com' or 'https://www.google.com')
        :param httpx_client: the underlying httpx client to pass to `whodap.lookup_domain`
        :return: instance of DomainLookup
        """
        _self = cls()
        top_level_domain = _self._get_top_level_domain(domain)
        response = whodap.lookup_domain(
            domain=_self.tld_extract_result.domain,
            tld=top_level_domain,
            httpx_client=httpx_client)
        _self._query = response.to_dict()
        # date keys are mismatched between projects; change these keys to the asyncwhois set.
        whois_dict = response.to_whois_dict()
        for a_key, b_key in [(TLDBaseKeys.EXPIRES, 'expires_date'),
                             (TLDBaseKeys.UPDATED, 'updated_date'),
                             (TLDBaseKeys.CREATED, 'created_date')]:
            whois_dict[a_key] = whois_dict.pop(b_key)
        _self._parser = whois_dict
        return _self

    @classmethod
    async def aio_rdap_domain(
        cls,
        domain: str,
        httpx_client: Any = None
    ):
        """
        Performs an async RDAP query using the `whodap` project.
        Stores the resulting RDAP output into "query_output" and a WHOIS friendly
        key:value pair dictionary into "parser_output".

        :param domain: the domain or URL to search (e.g. 'google.com' or 'https://www.google.com')
        :param httpx_client: the underlying httpx client to pass to `whodap.aio_lookup_domain`
        :return: instance of DomainLookup
        """
        _self = cls()
        top_level_domain = _self._get_top_level_domain(domain)
        response = await whodap.aio_lookup_domain(
            domain=_self.tld_extract_result.domain,
            tld=top_level_domain,
            httpx_client=httpx_client)
        _self._query = response.to_dict()
        whois_dict = response.to_whois_dict()
        # date keys are mismatched between projects; change these keys to the asyncwhois set.
        for a_key, b_key in [(TLDBaseKeys.EXPIRES, 'expires_date'),
                             (TLDBaseKeys.UPDATED, 'updated_date'),
                             (TLDBaseKeys.CREATED, 'created_date')]:
            whois_dict[a_key] = whois_dict.pop(b_key)
        _self._parser = whois_dict
        return _self


class NumberLookup(Lookup):

    def __init__(self):
        super().__init__()
        self._ip = None

    @property
    def ipv6(self) -> Optional[ipaddress.IPv6Address]:
        if isinstance(self._ip, ipaddress.IPv6Address):
            return self._ip

    @property
    def ipv4(self) -> Optional[ipaddress.IPv4Address]:
        if isinstance(self._ip, ipaddress.IPv4Address):
            return self._ip

    @staticmethod
    def convert_to_ip(ip: str):
        try:
            ip_obj = ipaddress.ip_address(ip)
            return ip_obj
        except ipaddress.AddressValueError:
            raise

    @classmethod
    def whois_ipv4(
        cls,
        ipv4: Union[str, ipaddress.IPv4Address],
        authoritative_only: bool,
        proxy_url: str,
        timeout: int
    ):
        _self = cls()
        if not isinstance(ipv4, ipaddress.IPv4Address):
            _self._ip = _self.convert_to_ip(ipv4)
        else:
            _self._ip = ipv4
        _, server = IPv4Allocations().get_servers(_self._ip)
        ip_string = str(_self._ip)
        # run the query
        query = NumberQuery.new(ip_string, server, authoritative_only, proxy_url, timeout)
        # parse the raw text output from the WHOIS server
        parser = NumberParser(query.authoritative_server)
        parser.parse(query.query_output)
        _self._query = query
        _self._parser = parser
        return _self

    @classmethod
    async def aio_whois_ipv4(
        cls,
        ipv4: Union[str, ipaddress.IPv4Address],
        authoritative_only: bool,
        proxy_url: str,
        timeout: int
    ):
        _self = cls()
        if not isinstance(ipv4, ipaddress.IPv4Address):
            _self._ip = _self.convert_to_ip(ipv4)
        else:
            _self._ip = ipv4
        _, server = IPv4Allocations().get_servers(_self._ip)
        ip_string = str(_self._ip)
        # run the query
        query = await NumberQuery.new_aio(ip_string, server, authoritative_only, proxy_url, timeout)
        # parse the raw text output from the WHOIS server
        parser = NumberParser(query.authoritative_server)
        parser.parse(query.query_output)
        _self._query = query
        _self._parser = parser
        return _self

    @classmethod
    def rdap_ipv4(
        cls,
        ipv4: Union[str, ipaddress.IPv4Address],
        httpx_client: Any = None
    ):
        _self = cls()
        response = whodap.lookup_ipv4(ipv4, httpx_client)
        _self._query = response.to_dict()
        _self._parser = None
        return _self

    @classmethod
    async def aio_rdap_ipv4(
        cls,
        ipv4: Union[str, ipaddress.IPv4Address],
        httpx_client: Any = None
    ):
        _self = cls()
        response = await whodap.aio_lookup_ipv4(ipv4, httpx_client)
        _self._query = response.to_dict()
        _self._parser = None
        return _self

    @classmethod
    def whois_ipv6(
        cls,
        ipv6: Union[str, ipaddress.IPv6Address],
        authoritative_only: bool,
        proxy_url: str,
        timeout: int
    ):
        _self = cls()
        if not isinstance(ipv6, ipaddress.IPv6Address):
            ipv6 = _self.convert_to_ip(ipv6)
        ip_string = str(ipv6)
        # run the query
        query = NumberQuery.new(ip_string, None, authoritative_only, proxy_url, timeout)
        # parse the raw text output from the WHOIS server
        parser = NumberParser(query.authoritative_server)
        parser.parse(query.query_output)
        _self._query = query
        _self._parser = parser
        return _self

    @classmethod
    async def aio_whois_ipv6(
        cls,
        ipv6: Union[str, ipaddress.IPv6Address],
        authoritative_only: bool,
        proxy_url: str,
        timeout: int
    ):
        _self = cls()
        if not isinstance(ipv6, ipaddress.IPv4Address):
            _self._ip = _self.convert_to_ip(ipv6)
        ip_string = str(_self._ip)
        # run the query
        query = await NumberQuery.new_aio(ip_string, None, authoritative_only, proxy_url, timeout)
        # parse the raw text output from the WHOIS server
        parser = NumberParser(query.authoritative_server)
        parser.parse(query.query_output)
        _self._query = query
        _self._parser = parser
        return _self

    @classmethod
    def rdap_ipv6(
        cls,
        ipv6: Union[str, ipaddress.IPv6Address],
        httpx_client: Any = None
    ):
        _self = cls()
        response = whodap.lookup_ipv6(ipv6, httpx_client)
        _self._query = response.to_dict()
        _self._parser = None
        return _self

    @classmethod
    async def aio_rdap_ipv6(
        cls,
        ipv6: Union[str, ipaddress.IPv6Address],
        httpx_client: Any = None
    ):
        _self = cls()
        response = await whodap.aio_lookup_ipv6(ipv6, httpx_client)
        _self._query = response.to_dict()
        _self._parser = None
        return _self


class ASNLookup(Lookup):

    def __init__(self):
        super().__init__()
        self.asn: int = None

    @classmethod
    def rdap_asn(
        cls,
        asn: int,
        httpx_client: Any = None
    ):
        _self = cls()
        response = whodap.lookup_asn(asn, httpx_client)
        _self._query = response.to_dict()
        _self._parser = None  # parser support not implemented
        return _self

    @classmethod
    async def aio_rdap_asn(
        cls,
        asn: int,
        httpx_client: Any = None
    ):
        _self = cls()
        response = await whodap.aio_lookup_asn(asn, httpx_client)
        _self._query = response.to_dict()
        _self._parser = None
        return _self