# https://docs.aiohttp.org/en/stable/web_quickstart.html
from aiohttp import web

import asyncwhois


async def whois_handler(request):
    domain = request.match_info.get('domain', 'google.com')
    result = await asyncwhois.aio_whois_domain(domain)
    return web.Response(
        text=f'WhoIs Query Parsed:\n{result.parser_output}\nQuery Output:\n{result.query_output}'
    )


app = web.Application()
app.add_routes([web.get('/whois/{domain}', whois_handler)])
web.run_app(app)

#
# Then navigate to localhost:8080/whois/<domain>
#
# --- examples ---
# localhost:8080/whois/netflix.com
# localhost:8080/whois/google.com
# localhost:8080/whois/pypi.org
#