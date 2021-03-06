"""
WHOIS Server Query module written in Python with asyncio support.

Copyright (c) 2020 Joe Obarzanek

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

import socket
import re
import asyncio
from typing import Tuple

from .errors import WhoIsQueryConnectError


class Query:

    _iana_server = "whois.iana.org"
    _whois_port = 43

    @staticmethod
    def _find_match(regex: str, blob: str) -> str:
        match = ""
        found = re.search(regex, blob, flags=re.IGNORECASE)
        if found:
            match = found.group(1).rstrip('\r')
        return match


class WhoIsQuery(Query):

    def __init__(self, domain: str, server: str = None, timeout: int = 10):
        self.domain = domain
        self.server = server
        self.timeout = timeout
        self.query_output = ""
        self._run()

    def _run(self):
        """
        Connects to the given WhoIs server on port 43, submits a query for the given domain,
        and saves the output into the "query_output" attribute. If server is not specified (defaults to None),
        then a connection to the IANA root is created first.
        """
        data = self.domain + "\r\n"
        try:
            # server is "None"
            if not self.server:
                # reach out to whois.iana.org:43 to find "refer"
                with self._create_connection((self._iana_server, self._whois_port), self.timeout) as conn:
                    iana_result_blob = self._send_and_recv(conn, data)
                    self.server = self._find_match(regex=r"refer: *(.+)", blob=iana_result_blob)
                    if not self.server:
                        raise WhoIsQueryConnectError(f"Could not find a whois server for {self.domain}")

            # connect to <server>:43
            with self._create_connection((self.server, self._whois_port), self.timeout) as conn:
                # save output into "query_output"
                self.query_output = self._send_and_recv(conn, data)
                # check for "authoritative" whois server via regex
                whois_server = self._find_match(regex=r"WHOIS server: *(.+)", blob=self.query_output)
                if whois_server:
                    # if there is a more authoritative source; connect and re-query
                    self.server = whois_server
                    with self._create_connection((self.server, self._whois_port), self.timeout) as conn:
                        # save output into "query_output"
                        self.query_output = self._send_and_recv(conn, data)
        except ConnectionResetError:
            server = self.server or self._iana_server
            raise WhoIsQueryConnectError(f'"Connection reset by peer" when communicating with {server}:43')
        except socket.timeout:
            server = self.server or self._iana_server
            raise WhoIsQueryConnectError(f'Socket timed out when attempting to reach {server}:43')

    @staticmethod
    def _send_and_recv(conn: socket.socket, data: str) -> str:
        conn.sendall(data.encode())
        result = ""
        while True:
            received = conn.recv(1024)
            if received == b"":
                break
            else:
                result += received.decode('utf-8', errors='ignore')
        return result

    @staticmethod
    def _create_connection(address: Tuple[str, int], timeout: int) -> socket.socket:
        try:
            return socket.create_connection(address=address, timeout=timeout)
        except socket.timeout:
            raise WhoIsQueryConnectError(f'Could not reach WHOIS server at {address[0]}:{address[1]}')
        except:
            raise


class AsyncWhoIsQuery(Query):

    def __init__(self, domain: str, server: str, timeout: int):
        self.domain = domain
        self.server = server
        self.timeout = timeout
        self.query_output = ""

    @classmethod
    async def create(cls, domain: str, server: str = None, timeout: int = 10):
        query = cls(domain, server, timeout)
        await query._run()
        return query

    async def _run(self) -> None:
        """
        Connects to the given WhoIs server on port 43, submits a query for the given domain,
        and saves the output into the "query_output" attribute. If server is not specified (defaults to None),
        then a connection to the IANA root is created first.
        """
        data = self.domain + "\r\n"
        try:
            if not self.server:
                reader, writer = await self._create_connection((self._iana_server, self._whois_port), self.timeout)
                iana_query_output = await self._send_and_recv(reader, writer, data)
                self.server = self._find_match(regex=r"refer: *(.+)", blob=iana_query_output)
                writer.close()
                await writer.wait_closed()
                if not self.server:
                    raise WhoIsQueryConnectError(f'Could not find a WHOIS server for {self.domain}')

            reader, writer = await self._create_connection((self.server, self._whois_port), self.timeout)
            self.query_output = await self._send_and_recv(reader, writer, data)
            whois_server = self._find_match(regex=r"WHOIS server: *(.+)", blob=self.query_output)
            if whois_server:
                self.server = whois_server
                reader, writer = await self._create_connection((self.server, self._whois_port), self.timeout)
                self.query_output = await self._send_and_recv(reader, writer, data)

            writer.close()
            await writer.wait_closed()
        except asyncio.TimeoutError:
            server = self.server or self._iana_server
            raise WhoIsQueryConnectError(f'Socket timed out when attempting to reach {server}:43')
        except ConnectionResetError:
            server = self.server or self._iana_server
            raise WhoIsQueryConnectError(f'"Connection reset by peer" when communicating with {server}:43')

    @staticmethod
    async def _send_and_recv(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, data: str) -> str:
        writer.write(data.encode())
        result = ""
        while True:
            received = await reader.read(1024)
            if received == b"":
                break
            else:
                result += received.decode('utf-8', errors='ignore')
        return result

    @staticmethod
    async def _create_connection(address: Tuple[str, int], timeout: int) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        future = asyncio.open_connection(*address)
        try:
            reader, writer = await asyncio.wait_for(future, timeout)
            return reader, writer
        except:
            raise WhoIsQueryConnectError(f'Could not reach WHOIS server at {address[0]}:{address[1]}')
