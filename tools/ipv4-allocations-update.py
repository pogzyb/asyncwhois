#!/usr/bin/env python

"""This tool can be used to update the list mapping between IPv4 blocks and
their RDAP & Whois servers.

Data is retrieved from
https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.xhtm

More specifically from
https://www.iana.org/assignments/ipv4-address-space/ipv4-address-space.csv

Then, parsed and converted to the structured used by asyncwhois.

This tool should (arguably) be piped to "black -" to enhance the readability
of the produced content and then redirected to a source file in asyncwhois.

e.g:

    $ ipv4allocs | black - > asyncwhois/servers/ipv4.py


This tool currently relies on pypi:`httpx` to perform HTTP(s) request and on
pypi:`netaddr` 3rd party module to minimize the number of entries produced in
the final structure

"""

import os.path
import sys
import asyncio
import csv
import textwrap
from datetime import datetime, timezone
from typing import NamedTuple, TextIO
from ipaddress import IPv4Network
from io import StringIO

from netaddr import IPSet
import httpx


class Servers(NamedTuple):
    """A tuple linking Matching whois and rdap servers altogether"""

    whois: tuple[str]
    rdap: tuple[str]


AllocationMapping = dict[Servers, IPSet]
"""The type of data produced by the :py:func:`parse` function."""


IPv4Allocations = dict[IPv4Network, dict[str, str]]
"""The data format used by asyncwhois"""


ALLOCATIONS_CSV_URL = (
    "https://www.iana.org/assignments/ipv4-address-space" "/ipv4-address-space.csv"
)
"""The URL of the IANA document containing of the list of whois/rdap servers
matching IPv4 blocks."""


async def retrieve_allocation_data(url: str) -> str:
    """Simply perform an HTTP GET query and return the text"""
    async with httpx.AsyncClient() as client:
        response = await client.get(url)
        return response.text


def parse(csv_file: TextIO) -> AllocationMapping:
    """From a given CSV text file, return a minimal AllocationMapping object
    (Servers -> :py:class:`netaddr.IPSet`)
    """
    servers_to_set: AllocationMapping = {}
    keys = ["WHOIS", "RDAP"]
    csv_raw = csv.DictReader(csv_file)
    for data in csv_raw:
        if any(data[key] for key in keys):
            servers = Servers(*[tuple(data[key].split("\n")) for key in keys])
            first_byte = data["Prefix"].split("/", maxsplit=1)[0].lstrip("0")
            network = f"{first_byte}.0.0.0/8"
            try:
                ipset = servers_to_set[servers]
            except KeyError:
                ipset = servers_to_set[servers] = IPSet()
            ipset.add(network)
    return servers_to_set


def compat(data: AllocationMapping) -> IPv4Allocations:
    """Given an AllocationMapping structure, return the structured currently
    used by asyncwhois (an IPv4Network -> Servers mapping)
    """
    return {
        IPv4Network(str(cidr)): {
            "rdap": servers.rdap[0],
            "whois": servers.whois[0],
        }
        for servers, ipset in data.items()
        for cidr in ipset.iter_cidrs()
    }


def create_module_file(allocations: IPv4Allocations) -> str:
    """Generate the output module content"""
    ts = datetime.now(tz=timezone.utc).strftime("%Y:%m:%d %H:%M:%S")
    progname = os.path.basename(sys.argv[0])
    mapping_type_name = "AllocationsT"
    return textwrap.dedent(
        f'''
    """
    This file has been generated by {progname} program on {ts} UTC

    If you need it updated, override this file content with {progname} output.
    """


    from ipaddress import IPv4Network


    {mapping_type_name} = dict[IPv4Network, dict[str, str]]


    IPV4_ALLOCATIONS: {mapping_type_name} = {allocations}


    __all__ = ("IPV4_ALLOCATIONS", "{mapping_type_name}")
    '''
    )


async def main() -> None:
    """Retrieve the allocation data, parse it and generate a basic data-only
    python module.
    """
    csv_content: str = await retrieve_allocation_data(ALLOCATIONS_CSV_URL)
    allocation_data = parse(StringIO(csv_content))
    print(create_module_file(compat(allocation_data)))


if __name__ == "__main__":
    asyncio.run(main())