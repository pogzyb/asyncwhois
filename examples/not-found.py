import asyncwhois


def main():
    non_existent_domain = "dasrewrdgdfgserw34.com"

    try:
        r = asyncwhois.whois_domain(non_existent_domain)
        print(r.query_output)
    except asyncwhois.NotFoundError:
        print("That domain does not exist, so we threw an error.")

    # suppress exception throwing for "not found" domains:
    result = asyncwhois.whois_domain(non_existent_domain, ignore_not_found=True)
    print(result.query_output)

    return


if __name__ == "__main__":
    main()
