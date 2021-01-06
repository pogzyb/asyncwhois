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

    # Opens a connection to the appropriate WhoIs server, submits the query, and parses the output.
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

**asyncio**

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
Top Level Domain Parsers are located in `asyncwhois/parser.py` and are based on those found in `richardpenman/pywhois`_.
For additional TLD support, simply create a new class like the one below:

.. code-block:: python

    class RegexORG(BaseParser):

       _org_expressions = {}  # the custom regular expressions needed to parse the output from this whois server

       def __init__(self):
           super().__init__()
           self.server = 'whois.pir.org' # the whois server for this TLD
           self.update_reg_expressions(self._org_expressions)


.. _richardpenman/pywhois: https://github.com/richardpenman/pywhois

Unfortunately, "the format of responses [from a Whois server] follow a semi-free text format". This means that
situations will arise where you may find yourself needing more control over how parsing happens. Fortunately, you can
override the "BaseParser.parse" method to suit your needs. Tests are obviously encouraged if you plan on doing this.

For example, this is a snippet of the output from running a "whois google.ir" command.

.. code-block:: python

    domain:	google.ir
    ascii:	google.ir
    remarks:	(Domain Holder) Google Inc.
    remarks:	(Domain Holder Address) 1600 Amphitheatre Parkway, Mountain View, CA, US
    holder-c:	go438-irnic
    ...


In this case, the address, city, state, and country can all be extracted from the the "registrant_address" field. So,
as seen below, the parse method is overwritten to include this extra step.

.. code-block:: python

    class RegexIR(BaseParser):

        _ir_expressions = {
            BaseKeys.UPDATED                    : r'last-updated: *(.+)',
            BaseKeys.EXPIRES                    : r'expire-date: *(.+)',
            BaseKeys.REGISTRANT_ORGANIZATION    : r'org: *(.+)',
            BaseKeys.REGISTRANT_NAME            : r'remarks:\s+\(Domain Holder\) *(.+)',
            BaseKeys.REGISTRANT_ADDRESS         : r'remarks:\s+\(Domain Holder Address\) *(.+)',
            BaseKeys.NAME_SERVERS               : r'nserver: *(.+)'
        }

        def __init__(self):
            super().__init__()
            self.server = 'whois.nic.ir'
            self.update_reg_expressions(self._ir_expressions)

        def parse(self, blob: str) -> Dict[str, Any]:
            """
            Custom address parsing is required.
            """
            parsed_output = {}
            for key, regex in self.reg_expressions.items():
                if key == BaseKeys.REGISTRANT_ADDRESS:
                    match = self.find_match(regex, blob)
                    # need to break up the address field
                    address, city, state, country = match.split(', ')
                    parsed_output[BaseKeys.REGISTRANT_ADDRESS] = address
                    parsed_output[BaseKeys.REGISTRANT_CITY] = city
                    parsed_output[BaseKeys.REGISTRANT_STATE] = state
                    parsed_output[BaseKeys.REGISTRANT_COUNTRY] = country
                elif not parsed_output.get(key):
                    parsed_output[key] = self.find_match(regex, blob, many=key in self.multiple_match_keys)

                # convert dates
                if key in self.date_keys and parsed_output.get(key, None):
                    parsed_output[key] = self._parse_date(parsed_output.get(key))

            return parsed_output
