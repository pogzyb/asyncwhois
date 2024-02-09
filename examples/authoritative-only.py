import asyncwhois


def main():
    domain = "google.com"

    # show the entire query-chain answer
    result = asyncwhois.whois_domain(domain, authoritative_only=False)  # default
    print(result.query_output)

    # only show the "authoritative" answer
    result = asyncwhois.whois_domain(domain, authoritative_only=True)
    print(result.query_output)

    return


if __name__ == "__main__":
    main()
