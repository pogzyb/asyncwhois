from pprint import pprint

import asyncwhois
import whodap
import httpx


def main():
    domain = "axe.pizza"

    # WHOIS
    client = asyncwhois.DomainClient(ignore_not_found=True)

    query_string, parsed_dict = client.whois(domain)
    pprint(query_string)
    pprint(parsed_dict)

    # RDAP

    # Simple client example:
    client = asyncwhois.DomainClient()
    query_string, parsed_dict = client.rdap(domain)
    pprint(query_string)
    pprint(parsed_dict)

    # Fully configurable client example:
    # Proxy with `httpx`
    whodap_client = whodap.DNSClient.new_client(
        httpx_client=httpx.Client(proxies="https://proxy:8080")
    )
    client = asyncwhois.DomainClient(whodap_client=whodap_client)
    query_output, parser_output = client.rdap(domain)

    # **EXTERNAL DEPENDENCY** for SOCKS Proxies (`httpx_socks`)
    from httpx_socks import SyncProxyTransport

    transport = SyncProxyTransport.from_url("socks5://localhost:9050")
    whodap_client = whodap.DNSClient.new_client(
        httpx_client=httpx.Client(transport=transport)
    )
    client = asyncwhois.DomainClient(whodap_client=whodap_client)
    query_string, parsed_dict = client.rdap(domain)
    return


if __name__ == "__main__":
    main()
