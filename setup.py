import setuptools

with open("README.rst", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="asyncwhois",
    version="0.1.0",
    author="Joseph Obarzanek",
    author_email="pogzyb@umich.edu",
    description="Async-compatible Python module for retrieving WHOIS information for domains.",
    long_description=long_description,
    long_description_content_type="text/markdown",
    install_requires=[
        "aiodns",
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
    python_requires=">=3.6",
)
