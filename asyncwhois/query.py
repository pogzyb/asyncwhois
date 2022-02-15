import asyncio
import re
import socket
import sys
from typing import Tuple, Generator
from contextlib import contextmanager
# different installs for async contextmanager based on python version
if sys.version_info < (3, 7):
    from async_generator import asynccontextmanager
else:
    from contextlib import asynccontextmanager

from python_socks.sync import Proxy
from python_socks.async_.asyncio import Proxy as AsyncProxy

BLOCKSIZE = 1024


class Query:
    iana_server = "whois.iana.org"
    whois_port = 43
    refer_regex = r"refer: *(.+)"
    whois_server_regex = r".+ whois server: *(.+)"

    def __init__(
        self,
        server: str = None,
        authoritative_only: bool = True,
        proxy_url: str = None,
        timeout: int = 10
    ):
        self.server = server
        self.authoritative_only = authoritative_only
        self.proxy_url = proxy_url
        self.timeout = timeout
        self.authoritative_server = ""
        self.query_output = ""
        self.query_chain = ""

    @staticmethod
    def _find_match(regex: str, blob: str) -> str:
        match = ""
        found = re.search(regex, blob, flags=re.IGNORECASE)
        if found:
            match = found.group(1).rstrip("\r").replace(" ", "").rstrip(":").rstrip("/")
        return match

    @contextmanager
    def _create_connection(
        self,
        address: Tuple[str, int],
        proxy_url: str = None
    ) -> Generator[socket.socket, None, None]:
        s = None
        try:
            # Use proxy if specified
            if proxy_url:
                proxy = Proxy.from_url(proxy_url)
                # proxy is a standard python socket in blocking mode
                s = proxy.connect(*address)
            else:
                # otherwise use socket
                s = socket.create_connection(address, self.timeout)
            yield s
        finally:
            if s and hasattr(s, "close"):
                s.close()

    @asynccontextmanager
    async def _aio_create_connection(
        self,
        address: Tuple[str, int],
        proxy_url: str = None
    ) -> Generator[Tuple[asyncio.StreamReader, asyncio.StreamWriter], None, None]:
        # init
        reader, writer = None, None
        # Use proxy if specified
        if proxy_url:
            proxy = AsyncProxy.from_url(proxy_url)
            # sock is a standard python socket in blocking mode
            sock = await proxy.connect(*address)
            # pass it to asyncio
            s = asyncio.open_connection(
                host=None,
                port=None,
                sock=sock)
        else:
            # otherwise use asyncio to open the connection
            s = asyncio.open_connection(*address)
        try:
            reader, writer = await asyncio.wait_for(s, self.timeout)
            yield reader, writer
        finally:
            if writer:
                writer.close()
                if hasattr(writer, "wait_closed"):
                    await writer.wait_closed()

    @staticmethod
    def _send_and_recv(conn: socket.socket, data: str) -> str:
        conn.sendall(data.encode())
        result = ""
        while True:
            received = conn.recv(BLOCKSIZE)
            if received == b"":
                break
            else:
                result += received.decode("utf-8", errors="ignore")
        return result

    @staticmethod
    async def _aio_send_and_recv(
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        data: str
    ) -> str:
        writer.write(data.encode())
        result = ""
        while True:
            received = await reader.read(BLOCKSIZE)
            if received == b"":
                break
            else:
                result += received.decode("utf-8", errors="ignore")
        return result

    def _do_query(self, server: str, data: str, regex: str) -> str:
        """
        Recursively submits WHOIS queries until it reaches the Authoritative Server.
        Additionally, if `authoritative_only` is False, all text output from server hops
        is saved into `query_chain`.
        """
        # save authoritative server
        self.authoritative_server = server
        # connect to whois://<server>:43
        with self._create_connection((server, self.whois_port), self.proxy_url) as conn:
            # submit domain and receive raw query output
            query_output = self._send_and_recv(conn, data)
            if not self.authoritative_only:
                # concatenate query outputs
                self.query_chain += query_output
            # parse response for the referred WHOIS server name
            whois_server = self._find_match(regex, query_output)
            whois_server = whois_server.lower()
            if whois_server and whois_server != server:
                # recursive call to find more authoritative server
                query_output = self._do_query(whois_server, data, self.whois_server_regex)
        # return the WHOIS query output
        return query_output

    async def _aio_do_query(self, server: str, data: str, regex: str):
        # connect to whois://<server>:43
        async with self._aio_create_connection((server, self.whois_port), self.proxy_url) as r_and_w:
            # socket reader and writer
            reader, writer = r_and_w
            # submit domain and receive raw query output
            query_output = await self._aio_send_and_recv(reader, writer, data)
            if not self.authoritative_only:
                # concatenate query outputs
                self.query_chain += query_output
            # parse response for the referred WHOIS server name
            whois_server = self._find_match(regex, query_output)
            whois_server = whois_server.lower()
            if whois_server and whois_server != server:
                # recursive call to find the authoritative server
                query_output = await self._aio_do_query(whois_server, data, self.whois_server_regex)
        # return the WHOIS query output
        return query_output


class DomainQuery(Query):

    def __init__(
        self,
        domain: str,
        server: str = None,
        authoritative_only: bool = True,
        proxy_url: str = None,
        timeout: int = 10
    ):
        super().__init__(server, authoritative_only, proxy_url, timeout)
        self.domain = domain

    @classmethod
    def new(
        cls,
        domain: str,
        server: str = None,
        authoritative_only: bool = True,
        proxy_url: str = None,
        timeout: int = 10
    ):
        _self = cls(domain, server, authoritative_only, proxy_url, timeout)
        data = domain + "\r\n"
        if not _self.server:
            server_regex = _self.refer_regex
            server = _self.iana_server
        else:
            server_regex = _self.whois_server_regex
            server = _self.server
        _self.query_output = _self._do_query(server, data, server_regex)
        return _self

    @classmethod
    async def new_aio(
        cls,
        domain: str,
        server: str = None,
        authoritative_only: bool = True,
        proxy_url: str = None,
        timeout: int = 10
    ):
        _self = cls(domain, server, authoritative_only, proxy_url, timeout)
        data = domain + "\r\n"
        if not _self.server:
            server_regex = _self.refer_regex
            server = _self.iana_server
        else:
            server_regex = _self.whois_server_regex
            server = _self.server
        _self.query_output = await _self._aio_do_query(server, data, server_regex)
        return _self


class NumberQuery(Query):

    def __init__(
        self,
        ip: str,  # ipv4 or ipv6
        server: str = None,
        authoritative_only: bool = True,
        proxy_url: str = None,
        timeout: int = 10
    ):
        super().__init__(server, authoritative_only, proxy_url, timeout)
        self.whois_server_regex = r"ReferralServer: *whois://(.+)"
        self.ip = ip

    @classmethod
    def new(
        cls,
        ip: str,  # ipv4 or ipv6; validation is handled by caller.
        server: str = None,
        authoritative_only: bool = False,
        proxy_url: str = None,
        timeout: int = 10
    ):
        _self = cls(ip, server, authoritative_only, proxy_url, timeout)
        data = ip + "\r\n"
        if ":" in ip:  # ipv6
            _self.refer_regex = r"whois: *(.+)"
        server = server or _self.iana_server
        _self.query_output = _self._do_query(server, data, _self.refer_regex)
        return _self

    @classmethod
    async def new_aio(
        cls,
        ip: str,
        server: str = None,
        authoritative_only: bool = False,
        proxy_url: str = None,
        timeout: int = 10
    ):
        _self = cls(ip, server, authoritative_only, proxy_url, timeout)
        data = ip + "\r\n"
        if ":" in ip:  # ipv6
            _self.refer_regex = r"whois: *(.+)"
        server = server or _self.iana_server
        _self.query_output = await _self._aio_do_query(server, data, _self.refer_regex)
        return _self
