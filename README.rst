.. image:: https://badge.fury.io/py/asyncwhois.svg
    :target: https://badge.fury.io/py/asyncwhois

.. image:: https://travis-ci.com/pogzyb/asyncwhois.svg?branch=master
    :target: https://travis-ci.com/pogzyb/asyncwhois
    
.. image:: https://codecov.io/gh/pogzyb/asyncwhois/branch/master/graph/badge.svg
    :target: https://codecov.io/gh/pogzyb/asyncwhois



asyncwhois
==========

asyncio-compatible Python module for performing WHOIS queries for any domain.


Installation
------------

.. code-block:: bash

    pip install asyncwhois

Quickstart
----------

.. code-block:: python

    # Connects to the appropriate WhoIs server, submits a query, and parses the output.
    result = asyncwhois.lookup('google.com')
    # [for asyncio] result = await asyncwhois.aio_lookup('google.com')
    result.query_output   # raw output from the whois server
    result.parser_output  # dictionary of key/values extracted from query_output


.. code-block:: python

    # Equivalent to running "whois <domain>" from the shell. Uses the "subprocess" package.
    result = asyncwhois.whois_cmd_shell('google.com')
    # [for asyncio] result = await asyncwhois.aio_whois_cmd_shell('google.com')
    result.query_output   # raw output from the whois server
    result.parser_output  # dictionary of key/values extracted from query_output

Examples
-------------
**standard**

.. code-block:: python

    from pprint import pprint
    import asyncwhois

    result = asyncwhois.lookup('bitcoin.org')
    pprint(result.parser_output)
    >>> {created: datetime.datetime(2008, 8, 18, 13, 19, 55),
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


**bulk standard**

.. code-block:: python

    import asyncwhois


    def main():
        urls = [
            'www.google.co.uk',
            'en.wikipedia.org/wiki/Pi',
            'https://twitch.tv',
            'https://www.bing.com/search?q=llama',
            'agar.io',
            '172.217.3.110'
        ]
        for url in urls:
            asyncwhois.lookup(url)


    if __name__ == '__main__':
        main()

**bulk asyncio**

.. code-block:: python

    import asyncio
    import asyncwhois


    async def main():
        urls = [
            'www.google.co.uk',
            'en.wikipedia.org/wiki/Pi',
            'https://twitch.tv',
            'https://www.bing.com/search?q=llama',
            'agar.io',
            '172.217.3.110'
        ]
        tasks = []
        for url in urls:
            awaitable = asyncwhois.aio_lookup(url)
            tasks.append(awaitable)

        await asyncio.gather(*tasks)


    if __name__ == '__main__':
        asyncio.run(main())

Contributions
-------------
Unfortunately, "the format of responses [from a Whois server] follow a semi-free text format". This means that
situations will arise where this module does not support parsing the output of a specific server, and you may find
yourself needing more control over how parsing happens. Fortunately, you can create customized parsers to suit
your needs.

Example: This is a snippet of the output from running the "whois google.be" command.

.. code-block:: python
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


In this case, the "name servers" are listed on separate lines. The default BaseParser regexes
won't find all of these server names. In order to accommodate this extra step, the "parse" method was
overwritten within the parser subclass as seen below:

.. code-block:: python
    class RegexBE(BaseParser):
        _be_expressions = {  # the base class (BaseParser) will handle these regexes
            BaseKeys.CREATED: r'Registered: *(.+)',
            BaseKeys.REGISTRAR: r'Registrar:\n.+Name: *(.+)',
            BaseKeys.REGISTRANT_NAME: r'Registrant:\n *(.+)'
        }

        def __init__(self):
            super().__init__()
            self.update_reg_expressions(self._be_expressions)

        def parse(self, blob: str) -> Dict[str, Any]:  # custom parsing is needed to extract all the name servers
            parsed_output = super().parse(blob)  # run normal parsing for other keys
            ns_match = re.search(r"Name servers: *(.+)Keys: ", blob, re.DOTALL)  # custom parsing for name servers
            if ns_match:
                parsed_output[BaseKeys.NAME_SERVERS] = [m.strip() for m in ns_match.group(1).split('\n') if m.strip()]
            return parsed_output
    ...

