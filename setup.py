import setuptools

version = '0.1.0'

setuptools.setup(
    name='asyncwhois',
    version=version,
    description='Async-compatible Python module for retrieving WHOIS information for domains.',
    long_description='',
    install_requires=[
        'aiodns',
    ],
    classifiers=[
        'Environment :: Web Environment',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Topic :: Internet :: WWW/HTTP',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 3',
    ],
    keywords='whois, python, asyncio',
    author='Joseph Obarzanek',
    author_email='pogzyb@umich.edu',
    url='https://github.com/pogzyb/asyncwhois',
    license='MIT',
    packages=['asyncwhois'],
    package_dir={'asyncwhois': 'asyncwhois'},
    extras_require={
        'better date conversion': ['python-dateutil']
    },
    python_requires='>=3.6',
    tests_require=['asynctest', 'simplejson'],
    include_package_data=True,
    zip_safe=False
)