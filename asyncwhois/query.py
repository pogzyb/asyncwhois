import logging
import asyncio


logger = logging.getLogger(__name__)


async def do_async_whois_query(domain: str) -> str:
    """
    Runs the "whois <domain>" command asynchronously in a different "Process".
    (stderr is captured but not used at this time; could also be parsed in the future).

    :param domain: The domain for the command: "whois <domain>"
    :return: Raw WhoIs output string
    """
    logger.debug(f'Running "whois" query for {domain}')
    # https://docs.python.org/3/library/asyncio-subprocess.html
    p = await asyncio.create_subprocess_shell(
        f"whois {domain}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    query_result, _ = await p.communicate()
    return query_result.decode()
