# async-pywhois
Async-compatible Python module for retrieving WHOIS information of domains. Based on [richardpenman/pywhois](https://github.com/richardpenman/pywhois)


Installation
-------

`pip install asyncwhois`

Examples
-------
 
#### asyncio
```python
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
        'imgur.com'
    ]
    tasks = []
    for url in urls:
        awaitable = asyncwhois.lookup(url)
        tasks.append(awaitable)

    await asyncio.gather(*tasks)


if __name__ == '__main__':
    start = time.time()
    asyncio.run(main())
    print(f'Done! [{round(time.time() - start, 4)}] seconds.')
```

