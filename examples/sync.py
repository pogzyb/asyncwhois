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
        'imgur.com',
        'https://www.amazon.co.jp',
        'github.com/explore',
        '172.217.3.110'
    ]
    for url in urls:
        asyncwhois.lookup(url)


if __name__ == '__main__':
    start = time.time()
    main()
    print(f'Done! [{round(time.time() - start, 4)}] seconds.')
