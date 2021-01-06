import unittest
import os

from asyncwhois.parser import WhoIsParser


class TestWhoIsParsers(unittest.TestCase):

    @staticmethod
    def get_txt(tld: str):
        with open(os.path.join(os.path.abspath(os.path.dirname(__file__)), f"samples/tld_{tld}.txt")) as txt_input:
            query_output = txt_input.read()
        return query_output

    def test_parser_com(self):
        query_output = self.get_txt('com')
        parser = WhoIsParser('com')
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
        parser = WhoIsParser('in')
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
        parser = WhoIsParser('top')
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
        parser = WhoIsParser('xyz')
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
        parser = WhoIsParser('ir')
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
        self.assertEqual(parser.parser_output.get("registrant_state"), "CA")
        self.assertEqual(parser.parser_output.get("registrant_country"), "US")
        self.assertEqual(parser.parser_output.get("registrant_zipcode"), None)
        self.assertEqual(parser.parser_output.get("registrant_address"), "1600 Amphitheatre Parkway")
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), None)
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_organization"), "Google Inc.")
        self.assertEqual(parser.parser_output.get("registrant_name"), "Google Inc.")

    def test_parser_icu(self):
        query_output = self.get_txt('icu')
        parser = WhoIsParser('icu')
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
        parser = WhoIsParser('ie')
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
        parser = WhoIsParser('uk')
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
        self.assertEqual(len(parser.parser_output.get("name_servers")), 1)
        self.assertEqual(len(parser.parser_output.get("status")), 0)

    def test_parser_cl(self):
        query_output = self.get_txt('cl')
        parser = WhoIsParser('cl')
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
        parser = WhoIsParser('be')
        parser.parse(query_output)
        # confirm dates
        created_date = parser.parser_output.get("created")
        self.assertEqual(created_date.year, 2000)
        self.assertEqual(created_date.month, 12)
        self.assertEqual(created_date.day, 12)
        self.assertEqual(parser.parser_output.get("registrar"), "MarkMonitor Inc.")
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_organization"), None)
        self.assertEqual(parser.parser_output.get("registrant_name"), None)

    def test_parser_de(self):
        query_output = self.get_txt('de')
        parser = WhoIsParser('de')
        parser.parse(query_output)

        self.assertEqual(len(parser.parser_output.get('status')), 1)

    def test_parse_us(self):
        query_output = self.get_txt('us')
        parser = WhoIsParser('us')
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
        parser = WhoIsParser('ar')
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
        parser = WhoIsParser('no')
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
        parser = WhoIsParser('ai')
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
        parser = WhoIsParser('me')
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
        parser = WhoIsParser('cc')
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
        parser = WhoIsParser('ru')
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
        parser = WhoIsParser('edu')
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
        self.assertEqual(parser.parser_output.get("registrant_state"), "MI")
        self.assertEqual(parser.parser_output.get("registrant_city"), "Ann Arbor")
        self.assertEqual(parser.parser_output.get("registrant_country"), "US")
        self.assertEqual(parser.parser_output.get("registrant_zipcode"), "48105-2785")
        self.assertEqual(parser.parser_output.get("registrant_address"), "4251 Plymouth Road")
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_organization"), "ITCS, Arbor Lakes")
        self.assertEqual(parser.parser_output.get("registrant_name"), "University of Michigan -- ITD")
        # misc
        self.assertEqual(len(parser.parser_output.get("name_servers")), 3)

    def test_parser_info(self):
        query_output = self.get_txt('info')
        parser = WhoIsParser('info')
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
        parser = WhoIsParser('fi')
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
        parser = WhoIsParser('kz')
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
        parser = WhoIsParser('si')
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
        parser = WhoIsParser('ae')
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
        parser = WhoIsParser('ve')
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
        parser = WhoIsParser('app')
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
        parser = WhoIsParser('cn')
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
        parser = WhoIsParser('co')
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
        parser = WhoIsParser('pl')
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
        parser = WhoIsParser('online')
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
