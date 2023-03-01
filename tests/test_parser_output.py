import unittest
import os

from asyncwhois.parse_tld import DomainParser


class TestTLDParsers(unittest.TestCase):

    @staticmethod
    def get_txt(tld: str):
        with open(os.path.join(os.path.abspath(os.path.dirname(__file__)), f"samples/tld_{tld}.txt"), encoding='utf-8') as txt_input:
            query_output = txt_input.read()
        return query_output

    def test_parser_com(self):
        query_output = self.get_txt('com')
        parser = DomainParser('com')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        updated_date = parser.parser_output.get("updated")
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(created_date.year, 1997)
        self.assertEqual(updated_date.year, 2019)
        self.assertEqual(expires_date.year, 2028)
        self.assertEqual(created_date.month, 9)
        self.assertEqual(updated_date.month, 9)
        self.assertEqual(expires_date.month, 9)
        self.assertEqual(created_date.day, 15)
        self.assertEqual(updated_date.day, 9)
        self.assertEqual(expires_date.day, 13)
        # geo
        self.assertEqual(parser.parser_output.get("registrant_state"), "CA")
        self.assertEqual(parser.parser_output.get("registrant_country"), "US")
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), "MarkMonitor, Inc.")
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_organization"), "Google LLC")
        # misc
        self.assertEqual(parser.parser_output.get("dnssec"), "unsigned")
        self.assertEqual(len(parser.parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser.parser_output.get("status")), 6)

    def test_parser_in(self):
        query_output = self.get_txt('in')
        parser = DomainParser('in')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        updated_date = parser.parser_output.get("updated")
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(created_date.year, 2007)
        self.assertEqual(updated_date.year, 2019)
        self.assertEqual(expires_date.year, 2020)
        self.assertEqual(created_date.month, 12)
        self.assertEqual(updated_date.month, 12)
        self.assertEqual(expires_date.month, 12)
        self.assertEqual(created_date.day, 1)
        self.assertEqual(updated_date.day, 1)
        self.assertEqual(expires_date.day, 1)
        # geo
        self.assertEqual(parser.parser_output.get("registrant_state"), "Rajasthan")
        self.assertEqual(parser.parser_output.get("registrant_country"), "IN")
        self.assertEqual(parser.parser_output.get("registrant_address"), None)
        self.assertEqual(parser.parser_output.get("registrant_zipcode"), None)

        self.assertEqual(parser.parser_output.get("dnssec"), "unsigned")
        self.assertEqual(len(parser.parser_output.get("name_servers")), 2)
        self.assertEqual(len(parser.parser_output.get("status")), 1)

    def test_parser_top(self):
        query_output = self.get_txt('top')
        parser = DomainParser('top')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        updated_date = parser.parser_output.get("updated")
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(created_date.year, 2020)
        self.assertEqual(updated_date.year, 2020)
        self.assertEqual(expires_date.year, 2021)
        self.assertEqual(created_date.month, 2)
        self.assertEqual(updated_date.month, 5)
        self.assertEqual(expires_date.month, 2)
        self.assertEqual(created_date.day, 25)
        self.assertEqual(updated_date.day, 22)
        self.assertEqual(expires_date.day, 25)
        # geo
        self.assertEqual(parser.parser_output.get("registrant_state"), "AZ")
        self.assertEqual(parser.parser_output.get("registrant_country"), "US")
        self.assertEqual(parser.parser_output.get("registrant_zipcode"), "85016")
        self.assertEqual(parser.parser_output.get("registrant_address"), "1928 E. Highland Ave. Ste F104 PMB# 255")
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), "NameSilo, LLC")
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_organization"), "See PrivacyGuardian.org")
        # misc
        self.assertEqual(parser.parser_output.get("dnssec"), "unsigned")
        self.assertEqual(len(parser.parser_output.get("name_servers")), 3)
        self.assertEqual(len(parser.parser_output.get("status")), 1)

    def test_parser_xyz(self):
        query_output = self.get_txt('xyz')
        parser = DomainParser('xyz')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        updated_date = parser.parser_output.get("updated")
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(created_date.year, 2019)
        self.assertEqual(updated_date.year, 1)
        self.assertEqual(expires_date.year, 2020)
        self.assertEqual(created_date.month, 10)
        self.assertEqual(updated_date.month, 1)
        self.assertEqual(expires_date.month, 10)
        self.assertEqual(created_date.day, 15)
        self.assertEqual(updated_date.day, 1)
        self.assertEqual(expires_date.day, 15)
        # geo
        self.assertEqual(parser.parser_output.get("registrant_state"), "Panama")
        self.assertEqual(parser.parser_output.get("registrant_country"), "PA")
        self.assertEqual(parser.parser_output.get("registrant_zipcode"), None)
        self.assertEqual(parser.parser_output.get("registrant_address"), "P.O. Box 0823-03411")
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), "NAMECHEAP INC")
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_organization"), "WhoisGuard, Inc.")
        self.assertEqual(parser.parser_output.get("registrant_name"), "WhoisGuard Protected")
        # misc
        self.assertEqual(parser.parser_output.get("dnssec"), "unsigned")
        self.assertEqual(len(parser.parser_output.get("name_servers")), 3)
        self.assertEqual(len(parser.parser_output.get("status")), 2)

    def test_parser_ir(self):
        query_output = self.get_txt('ir')
        parser = DomainParser('ir')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        self.assertEqual(created_date, None)
        updated_date = parser.parser_output.get("updated")
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(updated_date.year, 2019)
        self.assertEqual(expires_date.year, 2020)
        self.assertEqual(updated_date.month, 11)
        self.assertEqual(expires_date.month, 12)
        self.assertEqual(updated_date.day, 7)
        self.assertEqual(expires_date.day, 22)
        # geo
        self.assertEqual(parser.parser_output.get("registrant_state"), None)
        self.assertEqual(parser.parser_output.get("registrant_country"), None)
        self.assertEqual(parser.parser_output.get("registrant_zipcode"), None)
        self.assertEqual(parser.parser_output.get("registrant_address"), "1600 Amphitheatre Parkway, Mountain View, CA, US")
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), None)
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_organization"), "Google Inc.")
        self.assertEqual(parser.parser_output.get("registrant_name"), "Google Inc.")

    def test_parser_icu(self):
        query_output = self.get_txt('icu')
        parser = DomainParser('icu')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        updated_date = parser.parser_output.get("updated")
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(created_date.year, 2019)
        self.assertEqual(updated_date.year, 2019)
        self.assertEqual(expires_date.year, 2020)
        self.assertEqual(created_date.month, 5)
        self.assertEqual(updated_date.month, 10)
        self.assertEqual(expires_date.month, 5)
        self.assertEqual(created_date.day, 11)
        self.assertEqual(updated_date.day, 23)
        self.assertEqual(expires_date.day, 11)
        # geo
        self.assertEqual(parser.parser_output.get("registrant_state"), "Sind(en)")
        self.assertEqual(parser.parser_output.get("registrant_city"), "karachi")
        self.assertEqual(parser.parser_output.get("registrant_country"), "PK")
        self.assertEqual(parser.parser_output.get("registrant_zipcode"), "75640")
        self.assertEqual(parser.parser_output.get("registrant_address"), "Manzoor Colony")
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), "PDR Ltd. d/b/a PublicDomainRegistry.com")
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_organization"), None)
        self.assertEqual(parser.parser_output.get("registrant_name"), None)
        # misc
        self.assertEqual(parser.parser_output.get("dnssec"), "Unsigned")
        self.assertEqual(len(parser.parser_output.get("name_servers")), 2)
        self.assertEqual(len(parser.parser_output.get("status")), 4)

    def test_parser_ie(self):
        query_output = self.get_txt('ie')
        parser = DomainParser('ie')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(created_date.year, 2002)
        self.assertEqual(expires_date.year, 2021)
        self.assertEqual(created_date.month, 3)
        self.assertEqual(expires_date.month, 3)
        self.assertEqual(created_date.day, 21)
        self.assertEqual(expires_date.day, 21)
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), "Markmonitor Inc")
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_organization"), None)
        self.assertEqual(parser.parser_output.get("registrant_name"), "Google, Inc")
        # misc
        self.assertEqual(len(parser.parser_output.get("name_servers")), 3)
        self.assertEqual(len(parser.parser_output.get("status")), 1)

    def test_parser_uk(self):
        query_output = self.get_txt('uk')
        parser = DomainParser('uk')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        updated_date = parser.parser_output.get("updated")
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(created_date.year, 2014)
        self.assertEqual(updated_date.year, 2020)
        self.assertEqual(expires_date.year, 2021)
        self.assertEqual(created_date.month, 6)
        self.assertEqual(updated_date.month, 5)
        self.assertEqual(expires_date.month, 6)
        self.assertEqual(created_date.day, 11)
        self.assertEqual(updated_date.day, 10)
        self.assertEqual(expires_date.day, 11)
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), "Markmonitor Inc. t/a MarkMonitor Inc. [Tag = MARKMONITOR]")
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_organization"), None)
        self.assertEqual(parser.parser_output.get("registrant_name"), None)
        # misc
        self.assertEqual(len(parser.parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser.parser_output.get("status")), 1)

    def test_parser_cl(self):
        query_output = self.get_txt('cl')
        parser = DomainParser('cl')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(created_date.year, 2002)
        self.assertEqual(expires_date.year, 2020)
        self.assertEqual(created_date.month, 10)
        self.assertEqual(expires_date.month, 11)
        self.assertEqual(created_date.day, 22)
        self.assertEqual(expires_date.day, 20)
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), "MarkMonitor Inc.")
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_organization"), "Google LLC")
        self.assertEqual(parser.parser_output.get("registrant_name"), "Google LLC")
        # misc
        self.assertEqual(len(parser.parser_output.get("name_servers")), 4)

    def test_parser_be(self):
        query_output = self.get_txt('be')
        parser = DomainParser('be')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        self.assertEqual(created_date.year, 2000)
        self.assertEqual(created_date.month, 12)
        self.assertEqual(created_date.day, 12)
        self.assertEqual(parser.parser_output.get("registrar"), "MarkMonitor Inc.")
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_organization"), None)
        self.assertEqual(parser.parser_output.get("registrant_name"), "Not shown, please visit www.dnsbelgium.be for webbased whois.")

    def test_parser_de(self):
        query_output = self.get_txt('de')
        parser = DomainParser('de')
        parser.parse(query_output)

        self.assertEqual(len(parser.parser_output.get('status')), 1)

    def test_parse_ua(self):
        query_output = self.get_txt('ua')
        parser = DomainParser('ua')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        updated_date = parser.parser_output.get("updated")
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(created_date.year, 2002)
        self.assertEqual(updated_date.year, 2022)
        self.assertEqual(expires_date.year, 2023)
        self.assertEqual(created_date.month, 12)
        self.assertEqual(updated_date.month, 11)
        self.assertEqual(expires_date.month, 12)
        self.assertEqual(created_date.day, 4)
        self.assertEqual(updated_date.day, 2)
        self.assertEqual(expires_date.day, 4)
        # geo
        self.assertEqual(parser.parser_output.get("registrant_state"), "CA")
        self.assertEqual(parser.parser_output.get("registrant_city"), "Mountain View")
        self.assertEqual(parser.parser_output.get("registrant_country"), "US")
        self.assertEqual(parser.parser_output.get("registrant_zipcode"), "94043")
        self.assertEqual(parser.parser_output.get("registrant_address"), "1600 Amphitheatre Parkway")
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), "MarkMonitor Inc.")
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_organization"), None)
        self.assertEqual(parser.parser_output.get("registrant_name"), "Google LLC")
        # misc
        self.assertEqual(parser.parser_output.get("dnssec"), None)
        self.assertEqual(len(parser.parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser.parser_output.get("status")), 7)

    def test_parse_ua1(self):
        query_output = self.get_txt('ua1')
        parser = DomainParser('ua')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        updated_date = parser.parser_output.get("updated")
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(created_date.year, 2018)
        self.assertEqual(updated_date.year, 2021)
        self.assertEqual(expires_date.year, 2023)
        self.assertEqual(created_date.month, 11)
        self.assertEqual(updated_date.month, 10)
        self.assertEqual(expires_date.month, 10)
        self.assertEqual(created_date.day, 25)
        self.assertEqual(updated_date.day, 17)
        self.assertEqual(expires_date.day, 16)
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), "ua.imena")

    def test_parse_us(self):
        query_output = self.get_txt('us')
        parser = DomainParser('us')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        updated_date = parser.parser_output.get("updated")
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(created_date.year, 2002)
        self.assertEqual(updated_date.year, 2020)
        self.assertEqual(expires_date.year, 2021)
        self.assertEqual(created_date.month, 4)
        self.assertEqual(updated_date.month, 3)
        self.assertEqual(expires_date.month, 4)
        self.assertEqual(created_date.day, 19)
        self.assertEqual(updated_date.day, 22)
        self.assertEqual(expires_date.day, 18)
        # geo
        self.assertEqual(parser.parser_output.get("registrant_state"), "CA")
        self.assertEqual(parser.parser_output.get("registrant_city"), "Mountain View")
        self.assertEqual(parser.parser_output.get("registrant_country"), "US")
        self.assertEqual(parser.parser_output.get("registrant_zipcode"), "94043")
        self.assertEqual(parser.parser_output.get("registrant_address"), "1600 Amphitheatre Parkway")
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), "MarkMonitor, Inc.")
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_organization"), "Google LLC")
        self.assertEqual(parser.parser_output.get("registrant_name"), "Google Inc")
        # misc
        self.assertEqual(parser.parser_output.get("dnssec"), "unsigned")
        self.assertEqual(len(parser.parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser.parser_output.get("status")), 3)

    def test_parse_ar(self):
        query_output = self.get_txt('ar')
        parser = DomainParser('ar')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        updated_date = parser.parser_output.get("updated")
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(created_date.year, 2013)
        self.assertEqual(updated_date.year, 2019)
        self.assertEqual(expires_date.year, 2020)
        self.assertEqual(created_date.month, 10)
        self.assertEqual(updated_date.month, 11)
        self.assertEqual(expires_date.month, 11)
        self.assertEqual(created_date.day, 29)
        self.assertEqual(updated_date.day, 1)
        self.assertEqual(expires_date.day, 1)
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), "nicar")
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_name"), "GOOGLE INC.")
        # misc
        self.assertEqual(len(parser.parser_output.get("name_servers")), 2)
        self.assertEqual(len(parser.parser_output.get("status")), 0)

    def test_parse_no(self):
        query_output = self.get_txt('no')
        parser = DomainParser('no')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        updated_date = parser.parser_output.get("updated")
        expires_date = parser.parser_output.get("expires")
        self.assertIsNone(expires_date)
        self.assertEqual(created_date.year, 2001)
        self.assertEqual(updated_date.year, 2020)
        self.assertEqual(created_date.month, 2)
        self.assertEqual(updated_date.month, 1)
        self.assertEqual(created_date.day, 26)
        self.assertEqual(updated_date.day, 27)
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), "REG466-NORID")
        # misc
        self.assertEqual(len(parser.parser_output.get("name_servers")), 4)

    def test_parser_ai(self):
        query_output = self.get_txt('ai')
        parser = DomainParser('ai')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        updated_date = parser.parser_output.get("updated")
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(created_date.year, 2017)
        self.assertEqual(updated_date.year, 2019)
        self.assertEqual(expires_date.year, 2021)
        self.assertEqual(created_date.month, 12)
        self.assertEqual(updated_date.month, 8)
        self.assertEqual(expires_date.month, 9)
        self.assertEqual(created_date.day, 16)
        self.assertEqual(updated_date.day, 24)
        self.assertEqual(expires_date.day, 25)
        # geo
        self.assertEqual(parser.parser_output.get("registrant_state"), "CA")
        self.assertEqual(parser.parser_output.get("registrant_country"), "US")
        self.assertEqual(parser.parser_output.get("registrant_city"), "Mountain View")
        self.assertEqual(parser.parser_output.get("registrant_zipcode"), "94043")
        self.assertEqual(parser.parser_output.get("registrant_address"), "1600 Amphitheatre Parkway")
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), "Markmonitor")
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_organization"), "Google LLC")
        self.assertEqual(parser.parser_output.get("registrant_name"), "Domain Administrator")
        # misc
        self.assertEqual(parser.parser_output.get("dnssec"), "unsigned")
        self.assertEqual(len(parser.parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser.parser_output.get("status")), 3)

    def test_parser_me(self):
        query_output = self.get_txt('me')
        parser = DomainParser('me')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        updated_date = parser.parser_output.get("updated")
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(created_date.year, 2008)
        self.assertEqual(updated_date.year, 2020)
        self.assertEqual(expires_date.year, 2021)
        self.assertEqual(created_date.month, 6)
        self.assertEqual(updated_date.month, 5)
        self.assertEqual(expires_date.month, 6)
        self.assertEqual(created_date.day, 13)
        self.assertEqual(updated_date.day, 12)
        self.assertEqual(expires_date.day, 13)
        # geo
        self.assertEqual(parser.parser_output.get("registrant_state"), "CA")
        self.assertEqual(parser.parser_output.get("registrant_country"), "US")
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), "MarkMonitor Inc.")
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_organization"), "Google LLC")
        # misc
        self.assertEqual(parser.parser_output.get("dnssec"), "unsigned")
        self.assertEqual(len(parser.parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser.parser_output.get("status")), 6)

    def test_parser_cc(self):
        query_output = self.get_txt('cc')
        parser = DomainParser('cc')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        updated_date = parser.parser_output.get("updated")
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(created_date.year, 2002)
        self.assertEqual(updated_date.year, 2016)
        self.assertEqual(expires_date.year, 2024)
        self.assertEqual(created_date.month, 8)
        self.assertEqual(updated_date.month, 11)
        self.assertEqual(expires_date.month, 8)
        self.assertEqual(created_date.day, 4)
        self.assertEqual(updated_date.day, 12)
        self.assertEqual(expires_date.day, 4)
        # geo
        self.assertEqual(parser.parser_output.get("registrant_state"), "CA")
        self.assertEqual(parser.parser_output.get("registrant_city"), "Cupertino")
        self.assertEqual(parser.parser_output.get("registrant_country"), "US")
        self.assertEqual(parser.parser_output.get("registrant_zipcode"), "95014")
        self.assertEqual(parser.parser_output.get("registrant_address"), "1 Infinite Loop")
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), "CSC CORPORATE DOMAINS, INC.")
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_organization"), "Apple Inc.")
        self.assertEqual(parser.parser_output.get("registrant_name"), "Domain Administrator")
        # misc
        self.assertEqual(parser.parser_output.get("dnssec"), "unsigned")
        self.assertEqual(len(parser.parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser.parser_output.get("status")), 1)

    def test_parser_ru(self):
        query_output = self.get_txt('ru')
        parser = DomainParser('ru')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(created_date.year, 2004)
        self.assertEqual(expires_date.year, 2021)
        self.assertEqual(created_date.month, 3)
        self.assertEqual(expires_date.month, 3)
        self.assertEqual(created_date.day, 3)
        self.assertEqual(expires_date.day, 4)
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_organization"), "Google LLC")

    def test_parser_edu(self):
        query_output = self.get_txt('edu')
        parser = DomainParser('edu')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        updated_date = parser.parser_output.get("updated")
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(created_date.year, 1985)
        self.assertEqual(updated_date.year, 2020)
        self.assertEqual(expires_date.year, 2021)
        self.assertEqual(created_date.month, 10)
        self.assertEqual(updated_date.month, 12)
        self.assertEqual(expires_date.month, 7)
        self.assertEqual(created_date.day, 7)
        self.assertEqual(updated_date.day, 26)
        self.assertEqual(expires_date.day, 31)
        # geo
        self.assertEqual(parser.parser_output.get("registrant_state"), None)
        self.assertEqual(parser.parser_output.get("registrant_city"), None)
        self.assertEqual(parser.parser_output.get("registrant_country"), "US")
        self.assertEqual(parser.parser_output.get("registrant_zipcode"), None)
        self.assertEqual(parser.parser_output.get("registrant_address"),
                         'ITCS, Arbor Lakes, 4251 Plymouth Road, Ann Arbor, MI 48105-2785')
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_organization"), "University of Michigan -- ITD")
        self.assertEqual(parser.parser_output.get("registrant_name"), "University of Michigan -- ITD")
        # misc
        self.assertEqual(len(parser.parser_output.get("name_servers")), 3)

    def test_parser_info(self):
        query_output = self.get_txt('info')
        parser = DomainParser('info')
        parser.parse(query_output)
        created_date = parser.parser_output.get("created")
        updated_date = parser.parser_output.get("updated")
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(created_date.year, 2001)
        self.assertEqual(updated_date.year, 2020)
        self.assertEqual(expires_date.year, 2021)
        self.assertEqual(created_date.month, 7)
        self.assertEqual(updated_date.month, 6)
        self.assertEqual(expires_date.month, 7)
        self.assertEqual(created_date.day, 31)
        self.assertEqual(updated_date.day, 29)
        self.assertEqual(expires_date.day, 31)
        # geo
        self.assertEqual(parser.parser_output.get("registrar"), "MarkMonitor Inc.")
        self.assertEqual(parser.parser_output.get("registrant_state"), "CA")
        self.assertEqual(parser.parser_output.get("registrant_country"), "US")
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_organization"), "Google LLC")
        # misc
        self.assertEqual(len(parser.parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser.parser_output.get("status")), 6)

    def test_parser_fi(self):
        query_output = self.get_txt('fi')
        parser = DomainParser('fi')
        parser.parse(query_output)
        created_date = parser.parser_output.get("created")
        updated_date = parser.parser_output.get("updated")
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(created_date.year, 2006)
        self.assertEqual(updated_date.year, 2020)
        self.assertEqual(expires_date.year, 2021)
        self.assertEqual(created_date.month, 6)
        self.assertEqual(updated_date.month, 6)
        self.assertEqual(expires_date.month, 7)
        self.assertEqual(created_date.day, 30)
        self.assertEqual(updated_date.day, 2)
        self.assertEqual(expires_date.day, 4)
        self.assertEqual(parser.parser_output.get("registrar"), "MarkMonitor Inc.")
        # geo
        self.assertEqual(parser.parser_output.get("registrant_address"), "1600 Amphitheatre Parkway")
        self.assertEqual(parser.parser_output.get("registrant_zipcode"), "94043")
        self.assertEqual(parser.parser_output.get("registrant_city"), "Mountain View")
        self.assertEqual(parser.parser_output.get("registrant_country"), "United States of America")
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_name"), "Google LLC")
        # misc
        self.assertEqual(len(parser.parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser.parser_output.get("status")), 1)
        self.assertEqual(parser.parser_output.get("dnssec"), "no")

    def test_parser_kz(self):
        query_output = self.get_txt('kz')
        parser = DomainParser('kz')
        parser.parse(query_output)
        created_date = parser.parser_output.get("created")
        updated_date = parser.parser_output.get("updated")
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(created_date.year, 1999)
        self.assertEqual(updated_date.year, 2012)
        self.assertEqual(created_date.month, 6)
        self.assertEqual(updated_date.month, 11)
        self.assertEqual(created_date.day, 7)
        self.assertEqual(updated_date.day, 28)
        # geo
        self.assertEqual(parser.parser_output.get("registrant_address"), "2400 E. Bayshore Pkwy")
        self.assertEqual(parser.parser_output.get("registrant_zipcode"), "94043")
        self.assertEqual(parser.parser_output.get("registrant_city"), "Mountain View")
        self.assertEqual(parser.parser_output.get("registrant_country"), "US")
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_name"), "Google Inc.")
        self.assertEqual(parser.parser_output.get("registrant_organization"), "Google Inc.")
        # misc
        self.assertEqual(len(parser.parser_output.get("name_servers")), 2)
        self.assertEqual(len(parser.parser_output.get("status")), 1)
        self.assertEqual(parser.parser_output.get("registrar"), "KAZNIC")

    def test_parser_si(self):
        query_output = self.get_txt('si')
        parser = DomainParser('si')
        parser.parse(query_output)
        created_date = parser.parser_output.get("created")
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(created_date.year, 2005)
        self.assertEqual(expires_date.year, 2021)
        self.assertEqual(created_date.month, 4)
        self.assertEqual(expires_date.month, 7)
        self.assertEqual(created_date.day, 4)
        self.assertEqual(expires_date.day, 19)
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_name"), "G830057")
        # misc
        self.assertEqual(len(parser.parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser.parser_output.get("status")), 1)
        self.assertEqual(parser.parser_output.get("registrar"), "MarkMonitor")

    def test_parser_ae(self):
        query_output = self.get_txt('ae')
        parser = DomainParser('ae')
        parser.parse(query_output)
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_name"), "Domain Administrator")
        self.assertEqual(parser.parser_output.get("registrant_organization"), "Google LLC")
        # misc
        self.assertEqual(len(parser.parser_output.get("name_servers")), 2)
        self.assertEqual(len(parser.parser_output.get("status")), 2)
        self.assertEqual(parser.parser_output.get("registrar"), "MarkMonitor")

    def test_parser_ve(self):
        query_output = self.get_txt('ve')
        parser = DomainParser('ve')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        updated_date = parser.parser_output.get("updated")
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(created_date.year, 2002)
        self.assertEqual(updated_date.year, 2020)
        self.assertEqual(expires_date.year, 2021)
        self.assertEqual(created_date.month, 6)
        self.assertEqual(updated_date.month, 4)
        self.assertEqual(expires_date.month, 5)
        self.assertEqual(created_date.day, 5)
        self.assertEqual(updated_date.day, 24)
        self.assertEqual(expires_date.day, 6)
        # geo
        self.assertEqual(parser.parser_output.get("registrant_state"), "Ca")
        self.assertEqual(parser.parser_output.get("registrant_country"), "US")
        self.assertEqual(parser.parser_output.get("registrant_city"), "Mountain View")
        self.assertEqual(parser.parser_output.get("registrant_zipcode"), "94043")
        self.assertEqual(parser.parser_output.get("registrant_address"), "1600 Amphitheatre Parkway")
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), "NIC-VE")
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_organization"), "Google Llc")
        # misc
        self.assertEqual(len(parser.parser_output.get("name_servers")), 4)

    def test_parser_app(self):
        query_output = self.get_txt('app')
        parser = DomainParser('app')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        updated_date = parser.parser_output.get("updated")
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(created_date.year, 2018)
        self.assertEqual(updated_date.year, 2020)
        self.assertEqual(expires_date.year, 2021)
        self.assertEqual(created_date.month, 3)
        self.assertEqual(updated_date.month, 3)
        self.assertEqual(expires_date.month, 3)
        self.assertEqual(created_date.day, 29)
        self.assertEqual(updated_date.day, 2)
        self.assertEqual(expires_date.day, 29)
        # geo
        self.assertEqual(parser.parser_output.get("registrant_state"), "CA")
        self.assertEqual(parser.parser_output.get("registrant_country"), "US")
        self.assertEqual(parser.parser_output.get("registrant_city"), "REDACTED FOR PRIVACY")
        self.assertEqual(parser.parser_output.get("registrant_zipcode"), "REDACTED FOR PRIVACY")
        self.assertEqual(parser.parser_output.get("registrant_address"), "REDACTED FOR PRIVACY")
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), "MarkMonitor Inc.")
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_organization"), "Google LLC")
        # misc
        self.assertEqual(len(parser.parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser.parser_output.get("status")), 3)

    def test_parser_cn(self):
        query_output = self.get_txt('cn')
        parser = DomainParser('cn')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(created_date.year, 2003)
        self.assertEqual(expires_date.year, 2022)
        self.assertEqual(created_date.month, 3)
        self.assertEqual(expires_date.month, 3)
        self.assertEqual(created_date.day, 17)
        self.assertEqual(expires_date.day, 17)
        # geo
        self.assertEqual(parser.parser_output.get("registrant_name"), "北京谷翔信息技术有限公司")
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), "厦门易名科技股份有限公司")
        # registrant
        # misc
        self.assertEqual(len(parser.parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser.parser_output.get("status")), 5)
        self.assertEqual(parser.parser_output.get("dnssec"), "unsigned")

    def test_parser_co(self):
        query_output = self.get_txt('co')
        parser = DomainParser('co')
        parser.parse(query_output)
        created_date = parser.parser_output.get("created")
        updated_date = parser.parser_output.get("updated")
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(created_date.year, 2010)
        self.assertEqual(updated_date.year, 2020)
        self.assertEqual(expires_date.year, 2021)
        self.assertEqual(created_date.month, 2)
        self.assertEqual(updated_date.month, 1)
        self.assertEqual(expires_date.month, 2)
        self.assertEqual(created_date.day, 25)
        self.assertEqual(updated_date.day, 28)
        self.assertEqual(expires_date.day, 24)
        # geo
        self.assertEqual(parser.parser_output.get("registrant_address"), "REDACTED FOR PRIVACY")
        self.assertEqual(parser.parser_output.get("registrant_zipcode"), "REDACTED FOR PRIVACY")
        self.assertEqual(parser.parser_output.get("registrant_city"), "REDACTED FOR PRIVACY")
        self.assertEqual(parser.parser_output.get("registrant_country"), "US")
        self.assertEqual(parser.parser_output.get("registrant_state"), "CA")
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_name"), "REDACTED FOR PRIVACY")
        self.assertEqual(parser.parser_output.get("registrant_organization"), "Google Inc.")
        # misc
        self.assertEqual(len(parser.parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser.parser_output.get("status")), 3)
        self.assertEqual(parser.parser_output.get("registrar"), "MarkMonitor, Inc.")
        self.assertEqual(parser.parser_output.get("dnssec"), "unsigned")

    def test_parser_pl(self):
        query_output = self.get_txt('pl')
        parser = DomainParser('pl')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        updated_date = parser.parser_output.get("updated")
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(created_date.year, 2002)
        self.assertEqual(updated_date.year, 2020)
        self.assertEqual(expires_date.year, 2023)
        self.assertEqual(created_date.month, 9)
        self.assertEqual(updated_date.month, 8)
        self.assertEqual(expires_date.month, 10)
        self.assertEqual(created_date.day, 19)
        self.assertEqual(updated_date.day, 17)
        self.assertEqual(expires_date.day, 14)
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), "Markmonitor, Inc.")
        # misc
        self.assertEqual(parser.parser_output.get("dnssec"), "Unsigned")
        self.assertEqual(len(parser.parser_output.get("name_servers")), 4)

    def test_parser_online(self):
        query_output = self.get_txt('online')
        parser = DomainParser('online')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        updated_date = parser.parser_output.get("updated")
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(created_date.year, 2015)
        self.assertEqual(updated_date.year, 2020)
        self.assertEqual(expires_date.year, 2021)
        self.assertEqual(created_date.month, 8)
        self.assertEqual(updated_date.month, 8)
        self.assertEqual(expires_date.month, 8)
        self.assertEqual(created_date.day, 19)
        self.assertEqual(updated_date.day, 25)
        self.assertEqual(expires_date.day, 19)
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), "MarkMonitor, Inc (TLDs)")
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_organization"), "Google LLC")
        self.assertEqual(parser.parser_output.get("registrant_country"), "US")
        self.assertEqual(parser.parser_output.get("registrant_state"), "CA")
        # misc
        self.assertEqual(parser.parser_output.get("dnssec"), "unsigned")
        self.assertEqual(len(parser.parser_output.get("name_servers")), 4)

    def test_parser_buzz(self):
        query_output = self.get_txt('buzz')
        parser = DomainParser('buzz')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        updated_date = parser.parser_output.get("updated")
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(created_date.year, 2014)
        self.assertEqual(updated_date.year, 2020)
        self.assertEqual(expires_date.year, 2021)
        self.assertEqual(created_date.month, 3)
        self.assertEqual(updated_date.month, 2)
        self.assertEqual(expires_date.month, 3)
        self.assertEqual(created_date.day, 18)
        self.assertEqual(updated_date.day, 19)
        self.assertEqual(expires_date.day, 17)
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), "MarkMonitor, Inc.")
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_organization"), "Google LLC")
        self.assertEqual(parser.parser_output.get("registrant_country"), "US")
        self.assertEqual(parser.parser_output.get("registrant_state"), "CA")
        self.assertEqual(parser.parser_output.get("registrant_address"), "REDACTED FOR PRIVACY")
        self.assertEqual(parser.parser_output.get("registrant_city"), "REDACTED FOR PRIVACY")

    def test_parser_live(self):
        query_output = self.get_txt('live')
        parser = DomainParser('live')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        updated_date = parser.parser_output.get("updated")
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(created_date.year, 2015)
        self.assertEqual(updated_date.year, 2020)
        self.assertEqual(expires_date.year, 2021)
        self.assertEqual(created_date.month, 10)
        self.assertEqual(updated_date.month, 10)
        self.assertEqual(expires_date.month, 10)
        self.assertEqual(created_date.day, 19)
        self.assertEqual(updated_date.day, 19)
        self.assertEqual(expires_date.day, 19)
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), "Nom-iq Ltd. dba COM LAUDE")
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_organization"), "Amazon Technologies, Inc.")
        self.assertEqual(parser.parser_output.get("registrant_country"), "US")
        self.assertEqual(parser.parser_output.get("registrant_state"), "NV")
        self.assertEqual(parser.parser_output.get("registrant_address"), "REDACTED FOR PRIVACY")
        self.assertEqual(parser.parser_output.get("registrant_city"), "REDACTED FOR PRIVACY")

    def test_parser_cat(self):
        query_output = self.get_txt('cat')
        parser = DomainParser('cat')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        updated_date = parser.parser_output.get("updated")
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(created_date.year, 2006)
        self.assertEqual(updated_date.year, 2021)
        self.assertEqual(expires_date.year, 2022)
        self.assertEqual(created_date.month, 2)
        self.assertEqual(updated_date.month, 1)
        self.assertEqual(expires_date.month, 2)
        self.assertEqual(created_date.day, 14)
        self.assertEqual(updated_date.day, 15)
        self.assertEqual(expires_date.day, 14)
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), "MarkMonitor")
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_organization"), "Google LLC")
        self.assertEqual(parser.parser_output.get("registrant_country"), "US")
        self.assertEqual(parser.parser_output.get("registrant_state"), "CA")

    def test_parser_ma(self):
        query_output = self.get_txt('ma')
        parser = DomainParser('ma')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        updated_date = parser.parser_output.get("updated")
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(created_date.year, 2009)
        self.assertEqual(updated_date.year, 2020)
        self.assertEqual(expires_date.year, 2021)
        self.assertEqual(created_date.month, 3)
        self.assertEqual(updated_date.month, 2)
        self.assertEqual(expires_date.month, 3)
        self.assertEqual(created_date.day, 24)
        self.assertEqual(updated_date.day, 25)
        self.assertEqual(expires_date.day, 24)
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), "GENIOUS COMMUNICATION")
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_name"), "Google LLC")
        self.assertEqual(len(parser.parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser.parser_output.get("status")), 2)

    def test_parser_vg(self):
        query_output = self.get_txt('vg')
        parser = DomainParser('vg')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        updated_date = parser.parser_output.get("updated")
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(created_date.year, 1999)
        self.assertEqual(updated_date.year, 2020)
        self.assertEqual(expires_date.year, 2021)
        self.assertEqual(created_date.month, 6)
        self.assertEqual(updated_date.month, 12)
        self.assertEqual(expires_date.month, 6)
        self.assertEqual(created_date.day, 5)
        self.assertEqual(updated_date.day, 10)
        self.assertEqual(expires_date.day, 5)
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), "MarkMonitor, Inc.")
        self.assertEqual(len(parser.parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser.parser_output.get("status")), 3)

    def test_parser_tk(self):
        query_output = self.get_txt('tk')
        parser = DomainParser('tk')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(created_date.year, 2014)
        self.assertEqual(expires_date.year, 2021)
        self.assertEqual(created_date.month, 9)
        self.assertEqual(expires_date.month, 12)
        self.assertEqual(created_date.day, 17)
        self.assertEqual(expires_date.day, 11)
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), None)
        self.assertEqual(parser.parser_output.get("registrant_organization"), "Amazon Technologies, Inc.")
        self.assertEqual(parser.parser_output.get("registrant_name"), "Hostmaster Amazon Legal Dept.")
        self.assertEqual(len(parser.parser_output.get("name_servers")), 5)
        self.assertEqual(len(parser.parser_output.get("status")), 1)
        self.assertEqual(parser.parser_output.get("registrant_country"), "U.S.A.")
        self.assertEqual(parser.parser_output.get("registrant_state"), "Nevada")
        self.assertEqual(parser.parser_output.get("registrant_address"), "P.O. Box 8102")
        self.assertEqual(parser.parser_output.get("registrant_city"), "Reno")

    def test_parser_nl(self):
        query_output = self.get_txt('nl')
        parser = DomainParser('nl')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        updated_date = parser.parser_output.get("updated")
        self.assertEqual(created_date.year, 1999)
        self.assertEqual(updated_date.year, 2015)
        self.assertEqual(created_date.month, 5)
        self.assertEqual(updated_date.month, 12)
        self.assertEqual(created_date.day, 27)
        self.assertEqual(updated_date.day, 30)
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), "MarkMonitor Inc.")
        self.assertEqual(len(parser.parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser.parser_output.get("status")), 1)

    def test_parser_gq(self):
        query_output = self.get_txt('gq')
        parser = DomainParser('gq')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        self.assertEqual(created_date.year, 2014)
        self.assertEqual(created_date.month, 10)
        self.assertEqual(created_date.day, 14)
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), None)
        self.assertEqual(parser.parser_output.get("registrant_organization"), "Google Inc")
        self.assertEqual(parser.parser_output.get("registrant_name"), "DNS Admin")
        self.assertEqual(len(parser.parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser.parser_output.get("status")), 1)
        self.assertEqual(parser.parser_output.get("registrant_country"), "U.S.A.")
        self.assertEqual(parser.parser_output.get("registrant_state"), "California")
        self.assertEqual(parser.parser_output.get("registrant_address"), "1600 Amphitheatre Parkway")
        self.assertEqual(parser.parser_output.get("registrant_city"), "Mountain View")

    def test_tld_nu(self):
        query_output = self.get_txt('nu')
        parser = DomainParser('nu')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        self.assertEqual(created_date.year, 2011)
        self.assertEqual(created_date.month, 4)
        self.assertEqual(created_date.day, 15)
        updated_date = parser.parser_output.get("updated")
        self.assertEqual(updated_date.year, 2021)
        self.assertEqual(updated_date.month, 2)
        self.assertEqual(updated_date.day, 16)
        expired_date = parser.parser_output.get("expires")
        self.assertEqual(expired_date.year, 2022)
        self.assertEqual(expired_date.month, 4)
        self.assertEqual(expired_date.day, 15)
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), "Domeneshop AS")
        self.assertEqual(parser.parser_output.get("registrant_name"), "DNS1856879")
        self.assertEqual(len(parser.parser_output.get("name_servers")), 3)
        self.assertEqual(len(parser.parser_output.get("status")), 1)
        self.assertEqual(parser.parser_output.get("dnssec"), "signed delegation")

    def test_tld_is(self):
        query_output = self.get_txt('is')
        parser = DomainParser('is')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        self.assertEqual(created_date.year, 2000)
        self.assertEqual(created_date.month, 1)
        self.assertEqual(created_date.day, 18)
        expired_date = parser.parser_output.get("expires")
        self.assertEqual(expired_date.year, 2022)
        self.assertEqual(expired_date.month, 1)
        self.assertEqual(expired_date.day, 18)
        # registrar
        self.assertEqual(parser.parser_output.get("registrant_name"), "Amazon Europe Core S.a.r.l.")
        self.assertEqual(parser.parser_output.get("registrant_address"), "38 avenue John F. Kennedy, LU-L-1855 Luxembourg")
        self.assertEqual(len(parser.parser_output.get("name_servers")), 4)
        self.assertEqual(parser.parser_output.get("dnssec"), "unsigned delegation")

    def test_tld_cr(self):
        query_output = self.get_txt('cr')
        parser = DomainParser('cr')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        self.assertEqual(created_date.year, 2008)
        self.assertEqual(created_date.month, 3)
        self.assertEqual(created_date.day, 23)
        updated_date = parser.parser_output.get("updated")
        self.assertEqual(updated_date.year, 2021)
        self.assertEqual(updated_date.month, 2)
        self.assertEqual(updated_date.day, 5)
        expired_date = parser.parser_output.get("expires")
        self.assertEqual(expired_date.year, 2022)
        self.assertEqual(expired_date.month, 3)
        self.assertEqual(expired_date.day, 24)
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), "COMLAUDE")
        self.assertEqual(parser.parser_output.get("registrant_name"), "Amazon Technologies, Inc.")
        self.assertEqual(parser.parser_output.get("registrant_organization"), "Amazon Technologies, Inc.")
        self.assertEqual(parser.parser_output.get("registrant_address"), "P.O. Box 8102, Reno, 89507, Nevada, US")
        self.assertEqual(len(parser.parser_output.get("name_servers")), 9)

    def test_tld_cz(self):
        query_output = self.get_txt('cz')
        parser = DomainParser('cz')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        self.assertEqual(created_date.year, 1997)
        self.assertEqual(created_date.month, 9)
        self.assertEqual(created_date.day, 19)
        expired_date = parser.parser_output.get("expires")
        self.assertEqual(expired_date.year, 2021)
        self.assertEqual(expired_date.month, 10)
        self.assertEqual(expired_date.day, 28)
        updated_date = parser.parser_output.get("updated")
        self.assertEqual(updated_date.year, 2017)
        self.assertEqual(updated_date.month, 1)
        self.assertEqual(updated_date.day, 12)
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), "REG-NOMIQ")
        self.assertEqual(parser.parser_output.get("registrant_name"), "Legal Department")
        self.assertEqual(parser.parser_output.get("registrant_organization"), "Amazon Europe Holding Technologies SCS")
        self.assertEqual(parser.parser_output.get("registrant_address"), "65, boulevard Grande-Duchesse Charlotte, Luxembourg City, 1331, LU")
        self.assertEqual(len(parser.parser_output.get("name_servers")), 6)

    def test_tld_gg(self):
        query_output = self.get_txt('gg')
        parser = DomainParser('gg')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        self.assertEqual(created_date.year, 2003)
        self.assertEqual(created_date.month, 4)
        self.assertEqual(created_date.day, 30)
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_name"), "Google LLC")
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), "MarkMonitor Inc. (http://www.markmonitor.com)")
        # name servers and status
        self.assertEqual(len(parser.parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser.parser_output.get("status")), 4)

    def test_tld_ge(self):
        query_output = self.get_txt('ge')
        parser = DomainParser('ge')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        self.assertEqual(created_date.year, 2006)
        self.assertEqual(created_date.month, 7)
        self.assertEqual(created_date.day, 28)
        expired_date = parser.parser_output.get("expires")
        self.assertEqual(expired_date.year, 2021)
        self.assertEqual(expired_date.month, 7)
        self.assertEqual(expired_date.day, 29)
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_name"), "Google LLC")
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), "proservice ltd")
        # misc
        self.assertEqual(len(parser.parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser.parser_output.get("status")), 1)

    def test_tld_jp(self):
        query_output = self.get_txt('jp')
        parser = DomainParser('jp')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        self.assertEqual(created_date.year, 2010)
        self.assertEqual(created_date.month, 9)
        self.assertEqual(created_date.day, 22)
        #
        expires_date = parser.parser_output.get("expires")
        self.assertEqual(expires_date.year, 2021)
        self.assertEqual(expires_date.month, 9)
        self.assertEqual(expires_date.day, 30)
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_name"), "Amazon, Inc.")
        # address
        self.assertEqual(parser.parser_output.get("registrant_address"),
                         "Meguro-ku, Arco Tower Annex, 8-1, Shimomeguro 1-chome")
        # name servers
        self.assertEqual(len(parser.parser_output.get("name_servers")), 8)

    def test_tld_ax(self):
        query_output = self.get_txt('ax')
        parser = DomainParser('ax')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        self.assertEqual(created_date.year, 2016)
        self.assertEqual(created_date.month, 9)
        self.assertEqual(created_date.day, 8)
        expired_date = parser.parser_output.get("expires")
        self.assertEqual(expired_date.year, 2021)
        self.assertEqual(expired_date.month, 9)
        self.assertEqual(expired_date.day, 8)
        updated_date = parser.parser_output.get("updated")
        self.assertEqual(updated_date.year, 2020)
        self.assertEqual(updated_date.month, 9)
        self.assertEqual(updated_date.day, 5)
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_name"), "xTom GmbH")
        self.assertEqual(parser.parser_output.get("registrant_country"), "Tyskland")
        self.assertEqual(parser.parser_output.get("registrant_address"), "Kreuzstr.60, 40210, Duesseldorf")
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), "xTom")
        # misc
        self.assertEqual(len(parser.parser_output.get("name_servers")), 2)
        self.assertEqual(len(parser.parser_output.get("status")), 1)
        self.assertEqual(parser.parser_output.get("domain_name"), "google.ax")

    def test_tld_aw(self):
        query_output = self.get_txt('aw')
        parser = DomainParser('aw')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        self.assertEqual(created_date.year, 2017)
        self.assertEqual(created_date.month, 9)
        self.assertEqual(created_date.day, 13)
        updated_date = parser.parser_output.get("updated")
        self.assertEqual(updated_date.year, 2018)
        self.assertEqual(updated_date.month, 5)
        self.assertEqual(updated_date.day, 21)
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), "SETAR N.V.")
        # misc
        self.assertEqual(parser.parser_output.get("dnssec"), "no")
        self.assertEqual(len(parser.parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser.parser_output.get("status")), 1)
        self.assertEqual(parser.parser_output.get("domain_name"), "google.aw")
