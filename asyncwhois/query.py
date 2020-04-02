import logging
import asyncio


logger = logging.getLogger(__name__)


class WhoIsCommandFailure(Exception):
    pass


async def do_async_whois_query(domain: str, ignore_returncode: bool=True):
    """
    Runs the "whois <domain>" command in an asyncio subprocess shell.
    Captures stdout and stderr. Checks stderr if ignore_returncode is False.

    :param domain:
    :param ignore_returncode:
    :return: whois output string
    """
    logger.debug(f'Running "whois" query for _{domain}_')
    # https://docs.python.org/3/library/asyncio-subprocess.html
    p = await asyncio.create_subprocess_shell(
        f"whois {domain}",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE
    )
    query_result, stderr = await p.communicate()
    if not ignore_returncode and p.returncode != 0:
        raise WhoIsCommandFailure(query_result)
    return query_result.decode()
