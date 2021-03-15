import setuptools

with open("README.rst", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="asyncwhois",
    version="0.3.0",
    author="Joseph Obarzanek",
    author_email="pogzyb@umich.edu",
    description="asyncio-compatible Python module for performing WHOIS queries for any domain.",
    long_description=long_description,
    license="MIT",
    install_requires=[
        "aiodns>=2.0.0",
        "tldextract>=2.2.2"
    ],
    classifiers=[
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python",
        "Topic :: Internet :: WWW/HTTP",
        "Programming Language :: Python :: 3",
        "Framework :: AsyncIO"
    ],
    url="https://github.com/pogzyb/asyncwhois",
    packages=["asyncwhois"],
    package_dir={"asyncwhois": "asyncwhois"},
    python_requires=">=3.7",
    include_package_data=True
)
