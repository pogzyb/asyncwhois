import time

import asyncwhois


def main():
    urls = [
        'https://www.google.co.uk',
        'en.wikipedia.org/wiki/Pi',
        'https://www.urbandictionary.com/define.php?term=async',
        'twitch.tv',
        'https://www.pcpartpicker.com',
        'https://packaging.python.org/',
        'https://www.amazon.co.jp',
        'github.com/explore',
        'mango.beer'
    ]
    for url in urls:
        whois_data = asyncwhois.whois_domain(url)


if __name__ == '__main__':
    start = time.time()
    main()
    print(f'Done! [{round(time.time() - start, 4)}] seconds.')
