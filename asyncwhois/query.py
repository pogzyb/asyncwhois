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
            match = found.group(1).rstrip("\r").replace(" ", "").rstrip(":")
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

    @staticmethod
    async def _create_connection(address: Tuple[str, int], timeout: int) -> Tuple[
        asyncio.StreamReader, asyncio.StreamWriter]:
        future = asyncio.open_connection(*address)
        try:
            reader, writer = await asyncio.wait_for(future, timeout)
            return reader, writer
        except asyncio.TimeoutError:
            raise QueryError(f'Could not reach WHOIS server at {address[0]}:{address[1]}')
