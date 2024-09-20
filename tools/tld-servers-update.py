import textwrap
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

import httpx
import pandas as pd
import stamina
from bs4 import BeautifulSoup as bs


iana_root_db_uri = "https://www.iana.org/domains/root/db"


@stamina.retry(
    on=httpx.HTTPError,
    attempts=3,
    wait_initial=2.0,
    wait_jitter=2.0,
    wait_max=10.0,
)
def get_html(url: str) -> str:
    resp = httpx.get(url)
    resp.raise_for_status()
    return resp.text


def parse_root_db_table(root_db_html: str) -> list[tuple[str, str, str, str]]:
    tlds = []
    soup = bs(root_db_html, "html.parser")
    table = soup.find("table", attrs={"id": "tld-table"})
    table_body = table.find("tbody")
    rows = table_body.find_all("tr")
    for row in rows:
        cols = row.find_all("td")
        # tld and type
        tld, tld_type, _ = [v.get_text() for v in cols]
        # parse the "href" where server info is
        tld_link = cols[0].find("a")
        if tld_link is not None:
            href = f'https://www.iana.org{tld_link.get("href")}'
            # get the "urlsafe" tld
            tld_safe = href.split("/")[-1].replace(".html", "")
            tlds.append((tld.lstrip("\n."), tld_safe, href, tld_type))

    return tlds


def find_server_on_page(tld_html: str) -> str | None:
    soup = bs(tld_html, "html.parser")
    text = soup.get_text()
    start = text.find("WHOIS Server:")
    if start >= 0:
        end = text[start:].find("\n")
        whois_server_substring = text[start : start + end]
        whois_server = whois_server_substring.split(": ")[-1]
        return whois_server
    return None


def get_server(link: str):
    html = get_html(link)
    server = find_server_on_page(html)
    return server


def create_module_file(df: pd.DataFrame) -> str:

    def enc(x):
        return x.replace("-", "_").upper()

    cc_tlds_df = df.loc[df.tld_type == "country-code", :]
    country_code_tlds = ""
    for i, row in cc_tlds_df.iterrows():
        country_code_tlds += f"{enc(row.punycode)} = "
        if row.server_name is None:
            country_code_tlds += "None\n\t"
        else:
            country_code_tlds += f'"{row.server_name}"\n\t'

    g_tlds_df = df.loc[df.tld_type == "generic", :]
    generic_tlds = ""
    for i, row in g_tlds_df.iterrows():
        generic_tlds += f"{enc(row.punycode)} = "
        if row.server_name is None:
            generic_tlds += "None\n\t"
        else:
            generic_tlds += f'"{row.server_name}"\n\t'

    s_tlds_df = df.loc[df.tld_type == "sponsored", :]
    sponsored_tlds = ""
    for i, row in s_tlds_df.iterrows():
        sponsored_tlds += f"{enc(row.punycode)} = "
        if row.server_name is None:
            sponsored_tlds += "None\n\t"
        else:
            sponsored_tlds += f'"{row.server_name}"\n\t'

    ts = datetime.now(tz=timezone.utc).strftime("%Y:%m:%d %H:%M:%S")

    return f"""
# Extracted from the IANA Root Zone Database: https://www.iana.org/domains/root/db
# on {ts} UTC by https://github.com/pogzyb/asyncwhois/tools/tld-server-updates.py

class CountryCodeTLD: 
\t{country_code_tlds}

class GenericTLD: 
\t{generic_tlds}

class SponsoredTLD: 
\t{sponsored_tlds}
"""


def main():
    # iana_root_db_html = get_html(iana_root_db_uri)
    # tld_table_data = parse_root_db_table(iana_root_db_html)
    #
    # tld_server_info = []
    # with ThreadPoolExecutor(max_workers=2) as pool:
    #     server_parsers = {}
    #     for tld, tld_safe, href, tld_type in tld_table_data:
    #         server_parsers[pool.submit(get_server, href)] = (
    #             tld,
    #             tld_safe,
    #             tld_type,
    #             href,
    #         )
    #
    #     for server_parser in as_completed(server_parsers):
    #         tld, tld_safe, tld_type, href = server_parsers[server_parser]
    #         server_name = server_parser.result()
    #         tld_server_info.append((tld, tld_safe, tld_type, server_name, href))
    #
    # df = pd.DataFrame.from_records(
    #     tld_server_info, columns=["tld", "punycode", "tld_type", "server_name", "href"]
    # )
    # df.to_csv("tld_servers.csv", index=False)

    # for debugging:
    df = pd.read_csv("tld_servers.csv")
    df["server_name"] = df["server_name"].apply(lambda x: None if pd.isnull(x) else x)

    file_content = create_module_file(df)
    with open("domains.py", "w") as out:
        out.write(file_content)


if __name__ == "__main__":
    main()
