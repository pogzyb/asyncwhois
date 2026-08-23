from asyncwhois.parse import TLDBaseKeys
from asyncwhois.tldparsers import RegexBE, RegexDK, RegexHK, RegexRS


HK_SAMPLE = """
Domain Name:  GOOGLE.COM.HK
Domain Status: Active
DNSSEC:  unsigned
Registrar Name: MARKMONITOR INC.
Registrar Contact Information: Email: ccops@markmonitor.com

Registrant Contact Information:
Company English Name (It should be the same as the registered/corporation name on your Business Register Certificate or relevant documents): HONG KONG INTERNET HOLDING LIMITED
Company Chinese name:
Address:  RM 2203E NAN FUNG CENTRE
Country: Hong Kong (HK)
Email:  domainreg@webdomain.com.hk
Domain Name Commencement Date: 14-07-2001
Expiry Date: 20-11-2026

Administrative Contact Information:
Given name:  DOMAIN

Name Servers Information:
NS1.GOOGLE.COM
NS2.GOOGLE.COM
NS3.GOOGLE.COM
NS4.GOOGLE.COM
"""

BE_SAMPLE = """
Domain:\tgoogle.be
Status:\tNOT AVAILABLE
Registered:\tTue Dec 12 2000

Registrant:
\tNot shown, please visit www.dnsbelgium.be for webbased whois.

Registrar:
\tName:\tMarkmonitor Inc.
\tWebsite:\thttps://www.markmonitor.com

Nameservers:
\tns3.google.com
\tns1.google.com
\tns2.google.com
\tns4.google.com
"""

DK_SAMPLE = """
Domain:               google.dk
DNS:                  google.dk
Registered:           1999-01-10
Expires:              2027-03-31
Registrar:            MarkMonitor Inc.
DNSSEC:               Unsigned delegation
Status:               Active

Nameservers
Hostname:             ns1.google.com
Hostname:             ns2.google.com
Hostname:             ns3.google.com
Hostname:             ns4.google.com
"""

RS_SAMPLE = """
% The data in the Whois database are provided by RNIDS
Domain name: docs.rs
Domain status: Active https://www.rnids.rs/en/domain-name-status-codes#Active
Registration date: 24.03.2014 19:25:04
Modification date: 24.02.2026 16:53:10
Expiration date: 24.03.2030 19:25:04
Confirmed: 24.03.2014 19:25:04
Registrar: Webglobe d.o.o.

DNS: ns-1937.awsdns-50.co.uk -
DNS: ns-314.awsdns-39.com -
DNS: ns-779.awsdns-33.net -
DNS: ns-1397.awsdns-46.org -

DNSSEC signed: no
"""


def test_regex_hk_parses_nameservers_and_registrant_country_correctly():
    parsed = RegexHK().parse(HK_SAMPLE)

    assert parsed[TLDBaseKeys.REGISTRAR_ABUSE_EMAIL] == 'ccops@markmonitor.com'
    assert parsed[TLDBaseKeys.REGISTRAR_ABUSE_PHONE] is None
    assert parsed[TLDBaseKeys.REGISTRANT_COUNTRY] == 'Hong Kong (HK)'
    assert parsed[TLDBaseKeys.NAME_SERVERS] == [
        'NS1.GOOGLE.COM',
        'NS2.GOOGLE.COM',
        'NS3.GOOGLE.COM',
        'NS4.GOOGLE.COM',
    ]


def test_regex_be_parses_nameservers():
    parsed = RegexBE().parse(BE_SAMPLE)

    assert parsed[TLDBaseKeys.REGISTRANT_NAME] == 'Not shown, please visit www.dnsbelgium.be for webbased whois.'
    assert parsed[TLDBaseKeys.NAME_SERVERS] == [
        'ns3.google.com',
        'ns1.google.com',
        'ns2.google.com',
        'ns4.google.com',
    ]


def test_regex_dk_parses_hostname_nameservers():
    parsed = RegexDK().parse(DK_SAMPLE)

    assert parsed[TLDBaseKeys.NAME_SERVERS] == [
        'ns1.google.com',
        'ns2.google.com',
        'ns3.google.com',
        'ns4.google.com',
    ]


def test_regex_rs_uses_registration_date_as_created():
    parsed = RegexRS().parse(RS_SAMPLE)

    assert parsed[TLDBaseKeys.DOMAIN_NAME] == 'docs.rs'
    assert str(parsed[TLDBaseKeys.CREATED]).startswith('2014-03-24 19:25:04')
    assert parsed[TLDBaseKeys.REGISTRAR] == 'Webglobe d.o.o.'
    assert parsed[TLDBaseKeys.DNSSEC] == 'no'
    assert parsed[TLDBaseKeys.NAME_SERVERS] == [
        'ns-1937.awsdns-50.co.uk',
        'ns-314.awsdns-39.com',
        'ns-779.awsdns-33.net',
        'ns-1397.awsdns-46.org',
    ]
