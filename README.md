### asyncwhois

[![PyPI version](https://badge.fury.io/py/asyncwhois.svg)](https://badge.fury.io/py/asyncwhois)
[![Build Status](https://app.travis-ci.com/pogzyb/asyncwhois.svg?branch=master)](https://app.travis-ci.com/pogzyb/asyncwhois)
[![codecov](https://codecov.io/gh/pogzyb/asyncwhois/branch/master/graph/badge.svg?token=Q4xtgezXGX)](https://codecov.io/gh/pogzyb/asyncwhois)

`asyncwhois` | Python utility for performing WHOIS domain queries and parsing WHOIS text output.

#### Quickstart

```python
import asyncio
from pprint import pprint

import asyncwhois

# standard call
result = asyncwhois.lookup('www.google.com')
# result.query_output   # The semi-free text output from the whois server
# result.parser_output  # A dictionary of key/values extracted from query_output

# asyncio call
loop = asyncio.get_event_loop()
result = loop.run_until_complete(asyncwhois.aio_lookup('https://bitcoin.org'))

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

 # RDAP domain query
 result = asyncwhois.rdap_domain_lookup('https://google.com')

 # RDAP domain query via asyncio
 result = loop.run_until_complete(asyncwhois.aio_rdap_domain_lookup('https://google.com'))
 pprint(result.query_output)   # Raw RDAP query output as a dictionary
 pprint(result.parser_output)  # RDAP query output parsed/flattened into a WHOIS-like dictionary
```

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