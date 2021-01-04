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

**Dependencies**

.. code-block:: python

    tldextract>=2.2.2
    aiodns>=2.0.0

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
**normal**

.. code-block:: python

    import time

    import asyncwhois


    def main():
        urls = [
            'https://www.google.co.uk',
            'en.wikipedia.org/wiki/Pi',
            'https://www.urbandictionary.com/define.php?term=async',
            'twitch.tv',
            'reuters.com',
            'https://www.pcpartpicker.com',
            'https://packaging.python.org/',
            'imgur.com'
        ]
        for url in urls:
            asyncwhois.lookup(url)


    if __name__ == '__main__':
        start = time.time()
        main()
        print(f'Done! [{round(time.time() - start, 4)}] seconds.')


**asyncio**


.. code-block:: python

    import asyncio
    import time

    import asyncwhois


    async def main():
        urls = [
            'https://www.google.co.uk',
            'en.wikipedia.org/wiki/Pi',
            'https://www.urbandictionary.com/define.php?term=async',
            'twitch.tv',
            'reuters.com',
            'https://www.pcpartpicker.com',
            'https://packaging.python.org/',
            'imgur.com'
        ]
        tasks = []
        for url in urls:
            awaitable = asyncwhois.aio_lookup(url)
            tasks.append(awaitable)

        await asyncio.gather(*tasks)


    if __name__ == '__main__':
        start = time.time()
        asyncio.run(main())
        print(f'Done! [{round(time.time() - start, 4)}] seconds.')


**aiohttp**


.. code-block:: python

    from aiohttp import web
    import asyncwhois


    async def whois_handler(request):
        domain = request.match_info.get('domain', 'google.com')
        result = await asyncwhois.aio_lookup(domain)
        return web.Response(
            text=f'WhoIs Query Parsed:\n{result.parser_output}\nQuery Output:\n{result.query_output}'
        )



    app = web.Application()
    app.add_routes([web.get('/whois/{domain}', whois)])
    web.run_app(app)


Contributions
-------------
Parsers located in asyncwhois/parser.py are based on those found in `richardpenman/pywhois`_ .

For additional TLD support, simply created a new Regex Class containing:
    - "self.server" or the whois server for this TLD
    - "_<tld>_expressions" or the regexes that can extract and parse the output from this server

.. code-block:: python

    class RegexORG(BaseParser):

       _org_expressions = {}

       def __init__(self):
           super().__init__()
           self.server = 'whois.pir.org'
           self.update_reg_expressions(self._org_expressions)


.. _richardpenman/pywhois: https://github.com/richardpenman/pywhois
