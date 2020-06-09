import asyncio
import time

import asyncwhois


async def main():
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
    tasks = []
    for url in urls:
        awaitable = asyncwhois.aio_lookup(url)
        tasks.append(awaitable)

    await asyncio.gather(*tasks)


if __name__ == '__main__':
    start = time.time()
    asyncio.run(main())
    print(f'Done! [{round(time.time() - start, 4)}] seconds.')
