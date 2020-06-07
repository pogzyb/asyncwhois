import socket
import re
import asyncio
from typing import Tuple

from .errors import WhoIsQueryError


class Query:

    _iana_server = "whois.iana.org"
    _whois_port = 43

    def _find_match(self, regex: str, blob: str) -> str:
        match = ""
        found = re.search(regex, blob, flags=re.IGNORECASE)
        if found:
            match = found.group(1).rstrip('\r')
        return match


class WhoIsQuery(Query):

    def __init__(self, domain: str, server: str = None, timeout: int = 5):
        self.domain = domain
        self.server = server
        self.timeout = timeout
        self.query_output = ""
        self._run()

    def _run(self):
        data = self.domain + "\r\n"

        if not self.server:
            with self._create_connection((self._iana_server, self._whois_port)) as conn:
                iana_result_blob = self._send_and_recv(conn, data)
                self.server = self._find_match(regex=r"refer: *(.+)", blob=iana_result_blob)
                if not self.server:
                    raise WhoIsQueryError(f"Could not find a whois server for {self.domain}")

        with self._create_connection((self.server, self._whois_port)) as conn:
            self.query_output = self._send_and_recv(conn, data)
            whois_server = self._find_match(regex=r"WHOIS server: *(.+)", blob=self.query_output)
            if whois_server:
                self.server = whois_server
                with self._create_connection((self.server, self._whois_port)) as conn:
                    self.query_output = self._send_and_recv(conn, data)

    def _send_and_recv(self, conn: socket.socket, data: str) -> str:
        conn.sendall(data.encode())
        result = ""
        while True:
            received = conn.recv(1024)
            if received == b"":
                break
            else:
                result += received.decode('utf-8', errors='ignore')
        return result

    def _create_connection(self, address: Tuple[str, int]) -> socket.socket:
        try:
            return socket.create_connection(address=address, timeout=self.timeout)
        except:
            raise WhoIsQueryError(f'Could not reach WHOIS server at {address[0]}:{address[1]}')


class AsyncWhoIsQuery(Query):

    def __init__(self, domain: str, server: str, timeout: int):
        self.domain = domain
        self.server = server
        self.timeout = timeout
        self.query_output = ""

    @classmethod
    async def create(cls, domain: str, server: str = None, timeout: int = 5):
        query = cls(domain, server, timeout)
        await query._run()
        return query

    async def _run(self) -> None:
        data = self.domain + "\r\n"

        if not self.server:
            reader, writer = await self._create_connection(address=(self._iana_server, self._whois_port))
            iana_query_output = await self._send_and_recv(reader, writer, data)

            self.server = self._find_match(regex=r"refer: *(.+)", blob=iana_query_output)
            writer.close()
            await writer.wait_closed()
            if not self.server:
                raise WhoIsQueryError(f'Could not find a WHOIS server for {self.domain}')

        reader, writer = await self._create_connection((self.server, self._whois_port))
        self.query_output = await self._send_and_recv(reader, writer, data)
        whois_server = self._find_match(regex=r"WHOIS server: *(.+)", blob=self.query_output)
        if whois_server:
            self.server = whois_server
            reader, writer = await self._create_connection((self.server, self._whois_port))
            self.query_output = await self._send_and_recv(reader, writer, data)

        writer.close()
        await writer.wait_closed()

    async def _send_and_recv(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter, data: str) -> str:
        writer.write(data.encode())
        result = ""
        while True:
            received = await reader.read(1024)
            if received == b"":
                break
            else:
                result += received.decode()
        return result

    async def _create_connection(self, address: Tuple[str, int]) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        future = asyncio.open_connection(*address)
        try:
            reader, writer = await asyncio.wait_for(future, self.timeout)
            return reader, writer
        except:
            raise WhoIsQueryError(f'Could not reach WHOIS server at {address[0]}:{address[1]}')
