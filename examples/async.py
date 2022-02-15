import asyncio
import time

import asyncwhois


async def main():
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
    futures = []
    for url in urls:
        future = asyncwhois.whois_domain(url)
        futures.append(future)

    whois_data = await asyncio.gather(*futures)


if __name__ == '__main__':
    start = time.time()
    asyncio.run(main())
    print(f'Done! [{round(time.time() - start, 4)}] seconds.')
