### asyncwhois

[![PyPI version](https://badge.fury.io/py/asyncwhois.svg)](https://badge.fury.io/py/asyncwhois)
[![Build Status](https://app.travis-ci.com/pogzyb/asyncwhois.svg?branch=master)](https://app.travis-ci.com/pogzyb/asyncwhois)
[![codecov](https://codecov.io/gh/pogzyb/asyncwhois/branch/master/graph/badge.svg?token=Q4xtgezXGX)](https://codecov.io/gh/pogzyb/asyncwhois)

`asyncwhois` | Async-friendly Python library for WHOIS and RDAP queries.

#### Quickstart

```python
import asyncio
from pprint import pprint

import asyncwhois

# pick a domain
domain = 'bitcoin.org'
# domain could also be a URL; asyncwhois uses tldextract to parse the URL
domain = 'https://www.google.com?q=asyncwhois'

# standard call
result = asyncwhois.whois_domain(domain)
# result.query_output       # The semi-free text output from the whois server
# result.parser_output      # A dictionary of key:values extracted from query_output
# result.tld_extract_result # tldextract result (`tldextract.tldextract.ExtractResult`)

# asyncio call
loop = asyncio.get_event_loop()
result = loop.run_until_complete(asyncwhois.aio_whois_domain(domain))

pprint(result.parser_output)
"""
{created: datetime.datetime(2008, 8, 18, 13, 19, 55),
 dnssec: 'unsigned',
 domain_name: 'bitcoin.org',
 expires: datetime.datetime(2029, 8, 18, 13, 19, 55),
 name_servers: ['dns1.registrar-servers.com', 'dns2.registrar-servers.com'],
 registrant_address: 'P.O. Box 0823-03411',
 registrant_city: 'Panama',
 registrant_country: 'PA',
 registrant_name: 'WhoisGuard Protected',
 registrant_organization: 'WhoisGuard, Inc.',
 registrant_state: 'Panama',
 registrant_zipcode: '',
 registrar: 'NAMECHEAP INC',
 status: ['clientTransferProhibited '
          'https://icann.org/epp#clientTransferProhibited'],
 updated: datetime.datetime(2019, 11, 24, 13, 58, 35, 940000)}
 ...
 """
```

#### RDAP

The `whodap` (https://github.com/pogzyb/whodap) project is used behind the scenes to perform RDAP queries.

```python
# RDAP domain query
result = asyncwhois.rdap_domain('https://google.com')

# Async RDAP domain query
result = loop.run_until_complete(asyncwhois.aio_rdap_domain('https://google.com'))
pprint(result.query_output)         # Raw RDAP query output as a dictionary
pprint(result.parser_output)        # RDAP query output parsed/flattened into a WHOIS-like dictionary
print(result.tld_extract_result)    # tldextract result (`tldextract.tldextract.ExtractResult`)

```

#### Using Proxies

SOCKS4 and SOCKS5 proxies are supported for WHOIS and RDAP queries.

```python
tor_host = 'localhost'
tor_port = 9050

# WHOIS Queries with Proxy
result = asyncwhois.whois_domain(
    'bitcoin.org', proxy_url=f"socks5://{tor_host}:{tor_port}")
# or with auth...
tor_user = 'torpedo'
tor_pw = 'torpw'
result = asyncwhois.whois_ipv4(
    '8.8.8.8', proxy_url=f"socks5://{tor_user}:{tor_pw}@{tor_host}:{tor_port}")

# RDAP Queries with Proxy
import httpx

# EXTERNAL DEPENDENCY for SOCKS Proxies.
from httpx_socks import SyncProxyTransport, AsyncProxyTransport 

transport = SyncProxyTransport.from_url(f"socks5://{tor_host}:{tor_port}")
client = httpx.Client(transport=transport)
result = asyncwhois.rdap_ipv6('2001:4860:4860::8888', httpx_client=client)

transport = AsyncProxyTransport.from_url(f"socks5://{tor_user}:{tor_pw}@{tor_host}:{tor_port}")
async with httpx.AsyncClient(transport=transport) as client:
    result = await asyncwhois.aio_rdap_domain('bitcoin.org', httpx_client=client)

```

#### Exported Functions

| Function      | Description |
| ----------- | ----------- |
|  `whois_domain`          | WHOIS lookup for domain names     |
|  `whois_ipv4`            | WHOIS lookup for ipv4 addresses   |
|  `whois_ipv6`            | WHOIS lookup for ipv6 addresses   |
|  `rdap_domain`     | RDAP lookup for domain names      |
|  `rdap_ipv4`       | RDAP lookup for ipv4 addresses    |
|  `rdap_ipv6`       | RDAP lookup for ipv6 addresses    |
|  `rdap_asn`        | RDAP lookup for Autonomous System Numbers    |
|  `aio_whois_domain`      | async counterpart to `whois_domain`      |
|  `aio_whois_ipv4`        | async counterpart to `whois_ipv4`      |
|  `aio_whois_ipv6`        | async counterpart to `whois_ipv6`      |
|  `aio_rdap_domain` | async counterpart to `rdap_domain`      |
|  `aio_rdap_ipv4`   | async counterpart to `rdap_ipv4`      |
|  `aio_rdap_ipv6`   | async counterpart to `rdap_ipv6`      |
|  `aio_rdap_asn`    | async counterpart to `rdap_asn`      |

#### Contributions

Parsed output not what you expected? Unfortunately, "the format of responses [from a WHOIS server] follow a semi-free text format". Therefore,
situations will arise where this module does not support parsing the output from a specific server, and you may find
yourself needing more control over how parsing happens. Fortunately, you can create customized parsers to suit your needs.

Example: This is a snippet of the output from running the "whois google.be" command.
```python
Domain:	google.be
Status:	NOT AVAILABLE
Registered:	Tue Dec 12 2000

Registrant:
    Not shown, please visit www.dnsbelgium.be for webbased whois.

Registrar Technical Contacts:
    Organisation:	MarkMonitor Inc.
    Language:	en
    Phone:	+1.2083895740
    Fax:	+1.2083895771

Registrar:
    Name:	 MarkMonitor Inc.
    Website: http://www.markmonitor.com

Nameservers:
    ns2.google.com
    ns1.google.com
    ns4.google.com
    ns3.google.com

Keys:

Flags:
    clientTransferProhibited
...
```
In this case, the "name servers" are listed on separate lines. The default BaseParser regexes
won't find all of these server names. In order to accommodate this extra step, the "parse" method was
overwritten within the parser subclass as seen below:
```python
class RegexBE(BaseParser):
    _be_expressions = {  # the base class (BaseParser) will handle these regexes
        BaseKeys.CREATED: r'Registered: *(.+)',
        BaseKeys.REGISTRAR: r'Registrar:\n.+Name: *(.+)',
        BaseKeys.REGISTRANT_NAME: r'Registrant:\n *(.+)'
    }
    
    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._be_expressions)
    
    def parse(self, blob: str) -> Dict[str, Any]:
        # run base class parsing for other keys
        parsed_output = super().parse(blob)
        # custom parsing is needed to extract all the name servers
        ns_match = re.search(r"Name servers: *(.+)Keys: ", blob, re.DOTALL)
        if ns_match:
            parsed_output[BaseKeys.NAME_SERVERS] = [m.strip() for m in ns_match.group(1).split('\n') if m.strip()]
        return parsed_output
```