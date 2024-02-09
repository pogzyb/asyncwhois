import unittest
import os

from asyncwhois.parse_tld import DomainParser


class TestTLDParsers(unittest.TestCase):
    @staticmethod
    def get_txt(tld: str):
        with open(
            os.path.join(
                os.path.abspath(os.path.dirname(__file__)), f"samples/tld_{tld}.txt"
            ),
            encoding="utf-8",
        ) as txt_input:
            query_output = txt_input.read()
        return query_output

    def setUp(self):
        self.parser = DomainParser()

    def test_parser_com(self):
        query_output = self.get_txt("com")
        parser_output = self.parser.parse(query_output, "com")
        # confirm dates
        created_date = parser_output.get("created")
        updated_date = parser_output.get("updated")
        expires_date = parser_output.get("expires")
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
        self.assertEqual(parser_output.get("registrant_state"), "CA")
        self.assertEqual(parser_output.get("registrant_country"), "US")
        # registrar
        self.assertEqual(parser_output.get("registrar"), "MarkMonitor, Inc.")
        self.assertEqual(parser_output.get("registrar_iana_id"), "292")
        # registrant
        self.assertEqual(parser_output.get("registrant_organization"), "Google LLC")
        # misc
        self.assertEqual(parser_output.get("dnssec"), "unsigned")
        self.assertEqual(len(parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser_output.get("status")), 6)

    def test_parser_in(self):
        query_output = self.get_txt("in")
        parser_output = self.parser.parse(query_output, "in")
        # confirm dates
        created_date = parser_output.get("created")
        updated_date = parser_output.get("updated")
        expires_date = parser_output.get("expires")
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
        self.assertEqual(parser_output.get("registrant_state"), "Rajasthan")
        self.assertEqual(parser_output.get("registrant_country"), "IN")
        self.assertEqual(parser_output.get("registrant_address"), None)
        self.assertEqual(parser_output.get("registrant_zipcode"), None)

        self.assertEqual(parser_output.get("dnssec"), "unsigned")
        self.assertEqual(len(parser_output.get("name_servers")), 2)
        self.assertEqual(len(parser_output.get("status")), 1)

    def test_parser_top(self):
        query_output = self.get_txt("top")
        parser_output = self.parser.parse(query_output, "top")
        # confirm dates
        created_date = parser_output.get("created")
        updated_date = parser_output.get("updated")
        expires_date = parser_output.get("expires")
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
        self.assertEqual(parser_output.get("registrant_state"), "AZ")
        self.assertEqual(parser_output.get("registrant_country"), "US")
        self.assertEqual(parser_output.get("registrant_zipcode"), "85016")
        self.assertEqual(
            parser_output.get("registrant_address"),
            "1928 E. Highland Ave. Ste F104 PMB# 255",
        )
        # registrar
        self.assertEqual(parser_output.get("registrar"), "NameSilo, LLC")
        # registrant
        self.assertEqual(
            parser_output.get("registrant_organization"),
            "See PrivacyGuardian.org",
        )
        # misc
        self.assertEqual(parser_output.get("dnssec"), "unsigned")
        self.assertEqual(len(parser_output.get("name_servers")), 3)
        self.assertEqual(len(parser_output.get("status")), 1)

    def test_parser_xyz(self):
        query_output = self.get_txt("xyz")
        parser_output = self.parser.parse(query_output, "xyz")
        # confirm dates
        created_date = parser_output.get("created")
        updated_date = parser_output.get("updated")
        expires_date = parser_output.get("expires")
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
        self.assertEqual(parser_output.get("registrant_state"), "Panama")
        self.assertEqual(parser_output.get("registrant_country"), "PA")
        self.assertEqual(parser_output.get("registrant_zipcode"), None)
        self.assertEqual(parser_output.get("registrant_address"), "P.O. Box 0823-03411")
        # registrar
        self.assertEqual(parser_output.get("registrar"), "NAMECHEAP INC")
        # registrant
        self.assertEqual(
            parser_output.get("registrant_organization"), "WhoisGuard, Inc."
        )
        self.assertEqual(parser_output.get("registrant_name"), "WhoisGuard Protected")
        # misc
        self.assertEqual(parser_output.get("dnssec"), "unsigned")
        self.assertEqual(len(parser_output.get("name_servers")), 3)
        self.assertEqual(len(parser_output.get("status")), 2)

    def test_parser_ir(self):
        query_output = self.get_txt("ir")
        parser_output = self.parser.parse(query_output, "ir")
        # confirm dates
        created_date = parser_output.get("created")
        self.assertEqual(created_date, None)
        updated_date = parser_output.get("updated")
        expires_date = parser_output.get("expires")
        self.assertEqual(updated_date.year, 2019)
        self.assertEqual(expires_date.year, 2020)
        self.assertEqual(updated_date.month, 11)
        self.assertEqual(expires_date.month, 12)
        self.assertEqual(updated_date.day, 7)
        self.assertEqual(expires_date.day, 22)
        # geo
        self.assertEqual(parser_output.get("registrant_state"), None)
        self.assertEqual(parser_output.get("registrant_country"), None)
        self.assertEqual(parser_output.get("registrant_zipcode"), None)
        self.assertEqual(
            parser_output.get("registrant_address"),
            "1600 Amphitheatre Parkway, Mountain View, CA, US",
        )
        # registrar
        self.assertEqual(parser_output.get("registrar"), None)
        # registrant
        self.assertEqual(parser_output.get("registrant_organization"), "Google Inc.")
        self.assertEqual(parser_output.get("registrant_name"), "Google Inc.")

    def test_parser_icu(self):
        query_output = self.get_txt("icu")
        parser_output = self.parser.parse(query_output, "icu")
        # confirm dates
        created_date = parser_output.get("created")
        updated_date = parser_output.get("updated")
        expires_date = parser_output.get("expires")
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
        self.assertEqual(parser_output.get("registrant_state"), "Sind(en)")
        self.assertEqual(parser_output.get("registrant_city"), "karachi")
        self.assertEqual(parser_output.get("registrant_country"), "PK")
        self.assertEqual(parser_output.get("registrant_zipcode"), "75640")
        self.assertEqual(parser_output.get("registrant_address"), "Manzoor Colony")
        # registrar
        self.assertEqual(
            parser_output.get("registrar"),
            "PDR Ltd. d/b/a PublicDomainRegistry.com",
        )
        # registrant
        self.assertEqual(parser_output.get("registrant_organization"), None)
        self.assertEqual(parser_output.get("registrant_name"), None)
        # misc
        self.assertEqual(parser_output.get("dnssec"), "Unsigned")
        self.assertEqual(len(parser_output.get("name_servers")), 2)
        self.assertEqual(len(parser_output.get("status")), 4)

    def test_parser_ie(self):
        query_output = self.get_txt("ie")
        parser_output = self.parser.parse(query_output, "ie")
        # confirm dates
        created_date = parser_output.get("created")
        expires_date = parser_output.get("expires")
        self.assertEqual(created_date.year, 2002)
        self.assertEqual(expires_date.year, 2021)
        self.assertEqual(created_date.month, 3)
        self.assertEqual(expires_date.month, 3)
        self.assertEqual(created_date.day, 21)
        self.assertEqual(expires_date.day, 21)
        # registrar
        self.assertEqual(parser_output.get("registrar"), "Markmonitor Inc")
        # registrant
        self.assertEqual(parser_output.get("registrant_organization"), None)
        self.assertEqual(parser_output.get("registrant_name"), "Google, Inc")
        # misc
        self.assertEqual(len(parser_output.get("name_servers")), 3)
        self.assertEqual(len(parser_output.get("status")), 1)

    def test_parser_uk(self):
        query_output = self.get_txt("uk")
        parser_output = self.parser.parse(query_output, "uk")
        # confirm dates
        created_date = parser_output.get("created")
        updated_date = parser_output.get("updated")
        expires_date = parser_output.get("expires")
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
        self.assertEqual(
            parser_output.get("registrar"),
            "Markmonitor Inc. t/a MarkMonitor Inc. [Tag = MARKMONITOR]",
        )
        # registrant
        self.assertEqual(parser_output.get("registrant_organization"), None)
        self.assertEqual(parser_output.get("registrant_name"), None)
        # misc
        self.assertEqual(len(parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser_output.get("status")), 1)

    def test_parser_cl(self):
        query_output = self.get_txt("cl")
        tld = "cl"
        parser_output = self.parser.parse(query_output, "cl")
        # confirm dates
        created_date = parser_output.get("created")
        expires_date = parser_output.get("expires")
        self.assertEqual(created_date.year, 2002)
        self.assertEqual(expires_date.year, 2020)
        self.assertEqual(created_date.month, 10)
        self.assertEqual(expires_date.month, 11)
        self.assertEqual(created_date.day, 22)
        self.assertEqual(expires_date.day, 20)
        # registrar
        self.assertEqual(parser_output.get("registrar"), "MarkMonitor Inc.")
        # registrant
        self.assertEqual(parser_output.get("registrant_organization"), "Google LLC")
        self.assertEqual(parser_output.get("registrant_name"), "Google LLC")
        # misc
        self.assertEqual(len(parser_output.get("name_servers")), 4)

    def test_parser_be(self):
        query_output = self.get_txt("be")
        tld = "be"
        parser_output = self.parser.parse(query_output, tld)
        # confirm dates
        created_date = parser_output.get("created")
        self.assertEqual(created_date.year, 2000)
        self.assertEqual(created_date.month, 12)
        self.assertEqual(created_date.day, 12)
        self.assertEqual(parser_output.get("registrar"), "MarkMonitor Inc.")
        # registrant
        self.assertEqual(parser_output.get("registrant_organization"), None)
        self.assertEqual(
            parser_output.get("registrant_name"),
            "Not shown, please visit www.dnsbelgium.be for webbased whois.",
        )

    def test_parser_de(self):
        query_output = self.get_txt("de")
        tld = "de"
        parser_output = self.parser.parse(query_output, tld)

        self.assertEqual(len(parser_output.get("status")), 1)

    def test_parse_ua(self):
        query_output = self.get_txt("ua")
        tld = "ua"
        parser_output = self.parser.parse(query_output, tld)
        # confirm dates
        created_date = parser_output.get("created")
        updated_date = parser_output.get("updated")
        expires_date = parser_output.get("expires")
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
        self.assertEqual(parser_output.get("registrant_state"), "CA")
        self.assertEqual(parser_output.get("registrant_city"), "Mountain View")
        self.assertEqual(parser_output.get("registrant_country"), "US")
        self.assertEqual(parser_output.get("registrant_zipcode"), "94043")
        self.assertEqual(
            parser_output.get("registrant_address"), "1600 Amphitheatre Parkway"
        )
        # registrar
        self.assertEqual(parser_output.get("registrar"), "MarkMonitor Inc.")
        self.assertEqual(parser_output.get("registrar_url"), "http://markmonitor.com")
        self.assertEqual(
            parser_output.get("registrar_abuse_email"),
            "abusecomplaints@markmonitor.com",
        )
        # registrant
        self.assertEqual(parser_output.get("registrant_organization"), None)
        self.assertEqual(parser_output.get("registrant_name"), "Google LLC")
        # misc
        self.assertEqual(parser_output.get("dnssec"), None)
        self.assertEqual(len(parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser_output.get("status")), 7)

    def test_parse_ua1(self):
        query_output = self.get_txt("ua1")
        tld = "ua"
        parser_output = self.parser.parse(query_output, tld)
        # confirm dates
        created_date = parser_output.get("created")
        updated_date = parser_output.get("updated")
        expires_date = parser_output.get("expires")
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
        self.assertEqual(parser_output.get("registrar"), "ua.imena")

    def test_parse_us(self):
        query_output = self.get_txt("us")
        tld = "us"
        parser_output = self.parser.parse(query_output, tld)
        # confirm dates
        created_date = parser_output.get("created")
        updated_date = parser_output.get("updated")
        expires_date = parser_output.get("expires")
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
        self.assertEqual(parser_output.get("registrant_state"), "CA")
        self.assertEqual(parser_output.get("registrant_city"), "Mountain View")
        self.assertEqual(parser_output.get("registrant_country"), "US")
        self.assertEqual(parser_output.get("registrant_zipcode"), "94043")
        self.assertEqual(
            parser_output.get("registrant_address"), "1600 Amphitheatre Parkway"
        )
        # registrar
        self.assertEqual(parser_output.get("registrar"), "MarkMonitor, Inc.")
        # registrant
        self.assertEqual(parser_output.get("registrant_organization"), "Google LLC")
        self.assertEqual(parser_output.get("registrant_name"), "Google Inc")
        # misc
        self.assertEqual(parser_output.get("dnssec"), "unsigned")
        self.assertEqual(len(parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser_output.get("status")), 3)

    def test_parse_ar(self):
        query_output = self.get_txt("ar")
        tld = "ar"
        parser_output = self.parser.parse(query_output, tld)
        # confirm dates
        created_date = parser_output.get("created")
        updated_date = parser_output.get("updated")
        expires_date = parser_output.get("expires")
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
        self.assertEqual(parser_output.get("registrar"), "nicar")
        # registrant
        self.assertEqual(parser_output.get("registrant_name"), "GOOGLE INC.")
        # misc
        self.assertEqual(len(parser_output.get("name_servers")), 2)
        self.assertEqual(len(parser_output.get("status")), 0)

    def test_parse_no(self):
        query_output = self.get_txt("no")
        tld = "no"
        parser_output = self.parser.parse(query_output, tld)
        # confirm dates
        created_date = parser_output.get("created")
        updated_date = parser_output.get("updated")
        expires_date = parser_output.get("expires")
        self.assertIsNone(expires_date)
        self.assertEqual(created_date.year, 2001)
        self.assertEqual(updated_date.year, 2020)
        self.assertEqual(created_date.month, 2)
        self.assertEqual(updated_date.month, 1)
        self.assertEqual(created_date.day, 26)
        self.assertEqual(updated_date.day, 27)
        # registrar
        self.assertEqual(parser_output.get("registrar"), "REG466-NORID")
        # misc
        self.assertEqual(len(parser_output.get("name_servers")), 4)

    def test_parser_ai(self):
        query_output = self.get_txt("ai")
        tld = "ai"
        parser_output = self.parser.parse(query_output, tld)
        # confirm dates
        created_date = parser_output.get("created")
        updated_date = parser_output.get("updated")
        expires_date = parser_output.get("expires")
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
        self.assertEqual(parser_output.get("registrant_state"), "CA")
        self.assertEqual(parser_output.get("registrant_country"), "US")
        self.assertEqual(parser_output.get("registrant_city"), "Mountain View")
        self.assertEqual(parser_output.get("registrant_zipcode"), "94043")
        self.assertEqual(
            parser_output.get("registrant_address"), "1600 Amphitheatre Parkway"
        )
        # registrar
        self.assertEqual(parser_output.get("registrar"), "Markmonitor")
        # registrant
        self.assertEqual(parser_output.get("registrant_organization"), "Google LLC")
        self.assertEqual(parser_output.get("registrant_name"), "Domain Administrator")
        # misc
        self.assertEqual(parser_output.get("dnssec"), "unsigned")
        self.assertEqual(len(parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser_output.get("status")), 3)

    def test_parser_me(self):
        query_output = self.get_txt("me")
        tld = "me"
        parser_output = self.parser.parse(query_output, tld)
        # confirm dates
        created_date = parser_output.get("created")
        updated_date = parser_output.get("updated")
        expires_date = parser_output.get("expires")
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
        self.assertEqual(parser_output.get("registrant_state"), "CA")
        self.assertEqual(parser_output.get("registrant_country"), "US")
        # registrar
        self.assertEqual(parser_output.get("registrar"), "MarkMonitor Inc.")
        # registrant
        self.assertEqual(parser_output.get("registrant_organization"), "Google LLC")
        # misc
        self.assertEqual(parser_output.get("dnssec"), "unsigned")
        self.assertEqual(len(parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser_output.get("status")), 6)

    def test_parser_cc(self):
        query_output = self.get_txt("cc")
        tld = "cc"
        parser_output = self.parser.parse(query_output, tld)
        # confirm dates
        created_date = parser_output.get("created")
        updated_date = parser_output.get("updated")
        expires_date = parser_output.get("expires")
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
        self.assertEqual(parser_output.get("registrant_state"), "CA")
        self.assertEqual(parser_output.get("registrant_city"), "Cupertino")
        self.assertEqual(parser_output.get("registrant_country"), "US")
        self.assertEqual(parser_output.get("registrant_zipcode"), "95014")
        self.assertEqual(parser_output.get("registrant_address"), "1 Infinite Loop")
        # registrar
        self.assertEqual(parser_output.get("registrar"), "CSC CORPORATE DOMAINS, INC.")
        # registrant
        self.assertEqual(parser_output.get("registrant_organization"), "Apple Inc.")
        self.assertEqual(parser_output.get("registrant_name"), "Domain Administrator")
        # misc
        self.assertEqual(parser_output.get("dnssec"), "unsigned")
        self.assertEqual(len(parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser_output.get("status")), 1)

    def test_parser_ru(self):
        query_output = self.get_txt("ru")
        tld = "ru"
        parser_output = self.parser.parse(query_output, tld)
        # confirm dates
        created_date = parser_output.get("created")
        expires_date = parser_output.get("expires")
        self.assertEqual(created_date.year, 2004)
        self.assertEqual(expires_date.year, 2021)
        self.assertEqual(created_date.month, 3)
        self.assertEqual(expires_date.month, 3)
        self.assertEqual(created_date.day, 3)
        self.assertEqual(expires_date.day, 4)
        # registrant
        self.assertEqual(parser_output.get("registrant_organization"), "Google LLC")
        self.assertEqual(parser_output.get("admin_email"), "https://www.nic.ru/whois")

    def test_parser_edu(self):
        query_output = self.get_txt("edu")
        tld = "edu"
        parser_output = self.parser.parse(query_output, tld)
        # confirm dates
        created_date = parser_output.get("created")
        updated_date = parser_output.get("updated")
        expires_date = parser_output.get("expires")
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
        self.assertEqual(parser_output.get("registrant_state"), None)
        self.assertEqual(parser_output.get("registrant_city"), None)
        self.assertEqual(parser_output.get("registrant_country"), "US")
        self.assertEqual(parser_output.get("registrant_zipcode"), None)
        self.assertEqual(
            parser_output.get("registrant_address"),
            "ITCS, Arbor Lakes, 4251 Plymouth Road, Ann Arbor, MI 48105-2785",
        )
        # registrant
        self.assertEqual(
            parser_output.get("registrant_organization"),
            "University of Michigan -- ITD",
        )
        self.assertEqual(
            parser_output.get("registrant_name"), "University of Michigan -- ITD"
        )
        # misc
        self.assertEqual(len(parser_output.get("name_servers")), 3)

    def test_parser_info(self):
        query_output = self.get_txt("info")
        tld = "info"
        parser_output = self.parser.parse(query_output, tld)
        created_date = parser_output.get("created")
        updated_date = parser_output.get("updated")
        expires_date = parser_output.get("expires")
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
        self.assertEqual(parser_output.get("registrar"), "MarkMonitor Inc.")
        self.assertEqual(parser_output.get("registrant_state"), "CA")
        self.assertEqual(parser_output.get("registrant_country"), "US")
        # registrant
        self.assertEqual(parser_output.get("registrant_organization"), "Google LLC")
        # misc
        self.assertEqual(len(parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser_output.get("status")), 6)

    def test_parser_fi(self):
        query_output = self.get_txt("fi")
        tld = "fi"
        parser_output = self.parser.parse(query_output, tld)
        created_date = parser_output.get("created")
        updated_date = parser_output.get("updated")
        expires_date = parser_output.get("expires")
        self.assertEqual(created_date.year, 2006)
        self.assertEqual(updated_date.year, 2020)
        self.assertEqual(expires_date.year, 2021)
        self.assertEqual(created_date.month, 6)
        self.assertEqual(updated_date.month, 6)
        self.assertEqual(expires_date.month, 7)
        self.assertEqual(created_date.day, 30)
        self.assertEqual(updated_date.day, 2)
        self.assertEqual(expires_date.day, 4)
        self.assertEqual(parser_output.get("registrar"), "MarkMonitor Inc.")
        # geo
        self.assertEqual(
            parser_output.get("registrant_address"), "1600 Amphitheatre Parkway"
        )
        self.assertEqual(parser_output.get("registrant_zipcode"), "94043")
        self.assertEqual(parser_output.get("registrant_city"), "Mountain View")
        self.assertEqual(
            parser_output.get("registrant_country"), "United States of America"
        )
        # registrant
        self.assertEqual(parser_output.get("registrant_name"), "Google LLC")
        # misc
        self.assertEqual(len(parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser_output.get("status")), 1)
        self.assertEqual(parser_output.get("dnssec"), "no")

    def test_parser_kz(self):
        query_output = self.get_txt("kz")
        tld = "kz"
        parser_output = self.parser.parse(query_output, tld)
        created_date = parser_output.get("created")
        updated_date = parser_output.get("updated")
        expires_date = parser_output.get("expires")
        self.assertEqual(created_date.year, 1999)
        self.assertEqual(updated_date.year, 2012)
        self.assertEqual(created_date.month, 6)
        self.assertEqual(updated_date.month, 11)
        self.assertEqual(created_date.day, 7)
        self.assertEqual(updated_date.day, 28)
        # geo
        self.assertEqual(
            parser_output.get("registrant_address"), "2400 E. Bayshore Pkwy"
        )
        self.assertEqual(parser_output.get("registrant_zipcode"), "94043")
        self.assertEqual(parser_output.get("registrant_city"), "Mountain View")
        self.assertEqual(parser_output.get("registrant_country"), "US")
        # registrant
        self.assertEqual(parser_output.get("registrant_name"), "Google Inc.")
        self.assertEqual(parser_output.get("registrant_organization"), "Google Inc.")
        # misc
        self.assertEqual(len(parser_output.get("name_servers")), 2)
        self.assertEqual(len(parser_output.get("status")), 1)
        self.assertEqual(parser_output.get("registrar"), "KAZNIC")

    def test_parser_si(self):
        query_output = self.get_txt("si")
        tld = "si"
        parser_output = self.parser.parse(query_output, tld)
        created_date = parser_output.get("created")
        expires_date = parser_output.get("expires")
        self.assertEqual(created_date.year, 2005)
        self.assertEqual(expires_date.year, 2021)
        self.assertEqual(created_date.month, 4)
        self.assertEqual(expires_date.month, 7)
        self.assertEqual(created_date.day, 4)
        self.assertEqual(expires_date.day, 19)
        # registrant
        self.assertEqual(parser_output.get("registrant_name"), "G830057")
        # misc
        self.assertEqual(len(parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser_output.get("status")), 1)
        self.assertEqual(parser_output.get("registrar"), "MarkMonitor")

    def test_parser_ae(self):
        query_output = self.get_txt("ae")
        tld = "ae"
        parser_output = self.parser.parse(query_output, tld)
        # registrant
        self.assertEqual(parser_output.get("registrant_name"), "Domain Administrator")
        self.assertEqual(parser_output.get("registrant_organization"), "Google LLC")
        # misc
        self.assertEqual(len(parser_output.get("name_servers")), 2)
        self.assertEqual(len(parser_output.get("status")), 2)
        self.assertEqual(parser_output.get("registrar"), "MarkMonitor")

    def test_parser_ve(self):
        query_output = self.get_txt("ve")
        tld = "ve"
        parser_output = self.parser.parse(query_output, tld)
        # confirm dates
        created_date = parser_output.get("created")
        updated_date = parser_output.get("updated")
        expires_date = parser_output.get("expires")
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
        self.assertEqual(parser_output.get("registrant_state"), "Ca")
        self.assertEqual(parser_output.get("registrant_country"), "US")
        self.assertEqual(parser_output.get("registrant_city"), "Mountain View")
        self.assertEqual(parser_output.get("registrant_zipcode"), "94043")
        self.assertEqual(
            parser_output.get("registrant_address"), "1600 Amphitheatre Parkway"
        )
        # registrar
        self.assertEqual(parser_output.get("registrar"), "NIC-VE")
        # registrant
        self.assertEqual(parser_output.get("registrant_organization"), "Google Llc")
        # misc
        self.assertEqual(len(parser_output.get("name_servers")), 4)

    def test_parser_app(self):
        query_output = self.get_txt("app")
        tld = "app"
        parser_output = self.parser.parse(query_output, tld)
        # confirm dates
        created_date = parser_output.get("created")
        updated_date = parser_output.get("updated")
        expires_date = parser_output.get("expires")
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
        self.assertEqual(parser_output.get("registrant_state"), "CA")
        self.assertEqual(parser_output.get("registrant_country"), "US")
        self.assertEqual(parser_output.get("registrant_city"), "REDACTED FOR PRIVACY")
        self.assertEqual(
            parser_output.get("registrant_zipcode"), "REDACTED FOR PRIVACY"
        )
        self.assertEqual(
            parser_output.get("registrant_address"), "REDACTED FOR PRIVACY"
        )
        # registrar
        self.assertEqual(parser_output.get("registrar"), "MarkMonitor Inc.")
        # registrant
        self.assertEqual(parser_output.get("registrant_organization"), "Google LLC")
        # misc
        self.assertEqual(len(parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser_output.get("status")), 3)

    def test_parser_cn(self):
        query_output = self.get_txt("cn")
        tld = "cn"
        parser_output = self.parser.parse(query_output, tld)
        # confirm dates
        created_date = parser_output.get("created")
        expires_date = parser_output.get("expires")
        self.assertEqual(created_date.year, 2003)
        self.assertEqual(expires_date.year, 2022)
        self.assertEqual(created_date.month, 3)
        self.assertEqual(expires_date.month, 3)
        self.assertEqual(created_date.day, 17)
        self.assertEqual(expires_date.day, 17)
        # geo
        self.assertEqual(parser_output.get("registrant_name"), "北京谷翔信息技术有限公司")
        # registrar
        self.assertEqual(parser_output.get("registrar"), "厦门易名科技股份有限公司")
        # registrant
        # misc
        self.assertEqual(len(parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser_output.get("status")), 5)
        self.assertEqual(parser_output.get("dnssec"), "unsigned")

    def test_parser_co(self):
        query_output = self.get_txt("co")
        tld = "co"
        parser_output = self.parser.parse(query_output, tld)
        created_date = parser_output.get("created")
        updated_date = parser_output.get("updated")
        expires_date = parser_output.get("expires")
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
        self.assertEqual(
            parser_output.get("registrant_address"), "REDACTED FOR PRIVACY"
        )
        self.assertEqual(
            parser_output.get("registrant_zipcode"), "REDACTED FOR PRIVACY"
        )
        self.assertEqual(parser_output.get("registrant_city"), "REDACTED FOR PRIVACY")
        self.assertEqual(parser_output.get("registrant_country"), "US")
        self.assertEqual(parser_output.get("registrant_state"), "CA")
        # registrant
        self.assertEqual(parser_output.get("registrant_name"), "REDACTED FOR PRIVACY")
        self.assertEqual(parser_output.get("registrant_organization"), "Google Inc.")
        # misc
        self.assertEqual(len(parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser_output.get("status")), 3)
        self.assertEqual(parser_output.get("registrar"), "MarkMonitor, Inc.")
        self.assertEqual(parser_output.get("dnssec"), "unsigned")

    def test_parser_pl(self):
        query_output = self.get_txt("pl")
        tld = "pl"
        parser_output = self.parser.parse(query_output, tld)
        # confirm dates
        created_date = parser_output.get("created")
        updated_date = parser_output.get("updated")
        expires_date = parser_output.get("expires")
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
        self.assertEqual(parser_output.get("registrar"), "Markmonitor, Inc.")
        # misc
        self.assertEqual(parser_output.get("dnssec"), "Unsigned")
        self.assertEqual(len(parser_output.get("name_servers")), 4)

    def test_parser_online(self):
        query_output = self.get_txt("online")
        tld = "online"
        parser_output = self.parser.parse(query_output, tld)
        # confirm dates
        created_date = parser_output.get("created")
        updated_date = parser_output.get("updated")
        expires_date = parser_output.get("expires")
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
        self.assertEqual(parser_output.get("registrar"), "MarkMonitor, Inc (TLDs)")
        # registrant
        self.assertEqual(parser_output.get("registrant_organization"), "Google LLC")
        self.assertEqual(parser_output.get("registrant_country"), "US")
        self.assertEqual(parser_output.get("registrant_state"), "CA")
        # misc
        self.assertEqual(parser_output.get("dnssec"), "unsigned")
        self.assertEqual(len(parser_output.get("name_servers")), 4)

    def test_parser_buzz(self):
        query_output = self.get_txt("buzz")
        tld = "buzz"
        parser_output = self.parser.parse(query_output, tld)
        # confirm dates
        created_date = parser_output.get("created")
        updated_date = parser_output.get("updated")
        expires_date = parser_output.get("expires")
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
        self.assertEqual(parser_output.get("registrar"), "MarkMonitor, Inc.")
        # registrant
        self.assertEqual(parser_output.get("registrant_organization"), "Google LLC")
        self.assertEqual(parser_output.get("registrant_country"), "US")
        self.assertEqual(parser_output.get("registrant_state"), "CA")
        self.assertEqual(
            parser_output.get("registrant_address"), "REDACTED FOR PRIVACY"
        )
        self.assertEqual(parser_output.get("registrant_city"), "REDACTED FOR PRIVACY")

    def test_parser_live(self):
        query_output = self.get_txt("live")
        tld = "live"
        parser_output = self.parser.parse(query_output, tld)
        # confirm dates
        created_date = parser_output.get("created")
        updated_date = parser_output.get("updated")
        expires_date = parser_output.get("expires")
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
        self.assertEqual(parser_output.get("registrar"), "Nom-iq Ltd. dba COM LAUDE")
        # registrant
        self.assertEqual(
            parser_output.get("registrant_organization"),
            "Amazon Technologies, Inc.",
        )
        self.assertEqual(parser_output.get("registrant_country"), "US")
        self.assertEqual(parser_output.get("registrant_state"), "NV")
        self.assertEqual(
            parser_output.get("registrant_address"), "REDACTED FOR PRIVACY"
        )
        self.assertEqual(parser_output.get("registrant_city"), "REDACTED FOR PRIVACY")

    def test_parser_cat(self):
        query_output = self.get_txt("cat")
        tld = "cat"
        parser_output = self.parser.parse(query_output, tld)
        # confirm dates
        created_date = parser_output.get("created")
        updated_date = parser_output.get("updated")
        expires_date = parser_output.get("expires")
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
        self.assertEqual(parser_output.get("registrar"), "MarkMonitor")
        # registrant
        self.assertEqual(parser_output.get("registrant_organization"), "Google LLC")
        self.assertEqual(parser_output.get("registrant_country"), "US")
        self.assertEqual(parser_output.get("registrant_state"), "CA")

    def test_parser_ma(self):
        query_output = self.get_txt("ma")
        tld = "ma"
        parser_output = self.parser.parse(query_output, tld)
        # confirm dates
        created_date = parser_output.get("created")
        updated_date = parser_output.get("updated")
        expires_date = parser_output.get("expires")
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
        self.assertEqual(parser_output.get("registrar"), "GENIOUS COMMUNICATION")
        # registrant
        self.assertEqual(parser_output.get("registrant_name"), "Google LLC")
        self.assertEqual(len(parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser_output.get("status")), 2)

    def test_parser_vg(self):
        query_output = self.get_txt("vg")
        tld = "vg"
        parser_output = self.parser.parse(query_output, tld)
        # confirm dates
        created_date = parser_output.get("created")
        updated_date = parser_output.get("updated")
        expires_date = parser_output.get("expires")
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
        self.assertEqual(parser_output.get("registrar"), "MarkMonitor, Inc.")
        self.assertEqual(len(parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser_output.get("status")), 3)

    def test_parser_tk(self):
        query_output = self.get_txt("tk")
        tld = "tk"
        parser_output = self.parser.parse(query_output, tld)
        # confirm dates
        created_date = parser_output.get("created")
        expires_date = parser_output.get("expires")
        self.assertEqual(created_date.year, 2014)
        self.assertEqual(expires_date.year, 2021)
        self.assertEqual(created_date.month, 9)
        self.assertEqual(expires_date.month, 12)
        self.assertEqual(created_date.day, 17)
        self.assertEqual(expires_date.day, 11)
        # registrar
        self.assertEqual(parser_output.get("registrar"), None)
        self.assertEqual(
            parser_output.get("registrant_organization"),
            "Amazon Technologies, Inc.",
        )
        self.assertEqual(
            parser_output.get("registrant_name"), "Hostmaster Amazon Legal Dept."
        )
        self.assertEqual(len(parser_output.get("name_servers")), 5)
        self.assertEqual(len(parser_output.get("status")), 1)
        self.assertEqual(parser_output.get("registrant_country"), "U.S.A.")
        self.assertEqual(parser_output.get("registrant_state"), "Nevada")
        self.assertEqual(parser_output.get("registrant_address"), "P.O. Box 8102")
        self.assertEqual(parser_output.get("registrant_city"), "Reno")

    def test_parser_nl(self):
        query_output = self.get_txt("nl")
        tld = "nl"
        parser_output = self.parser.parse(query_output, tld)
        # confirm dates
        created_date = parser_output.get("created")
        updated_date = parser_output.get("updated")
        self.assertEqual(created_date.year, 1999)
        self.assertEqual(updated_date.year, 2015)
        self.assertEqual(created_date.month, 5)
        self.assertEqual(updated_date.month, 12)
        self.assertEqual(created_date.day, 27)
        self.assertEqual(updated_date.day, 30)
        # registrar
        self.assertEqual(parser_output.get("registrar"), "MarkMonitor Inc.")
        self.assertEqual(parser_output.get("registrar"), "MarkMonitor Inc.")
        self.assertEqual(len(parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser_output.get("status")), 1)

    def test_parser_gq(self):
        query_output = self.get_txt("gq")
        tld = "gq"
        parser_output = self.parser.parse(query_output, tld)
        # confirm dates
        created_date = parser_output.get("created")
        self.assertEqual(created_date.year, 2014)
        self.assertEqual(created_date.month, 10)
        self.assertEqual(created_date.day, 14)
        # registrar
        self.assertEqual(parser_output.get("registrar"), None)
        self.assertEqual(parser_output.get("registrant_organization"), "Google Inc")
        self.assertEqual(parser_output.get("registrant_name"), "DNS Admin")
        self.assertEqual(len(parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser_output.get("status")), 1)
        self.assertEqual(parser_output.get("registrant_country"), "U.S.A.")
        self.assertEqual(parser_output.get("registrant_state"), "California")
        self.assertEqual(
            parser_output.get("registrant_address"), "1600 Amphitheatre Parkway"
        )
        self.assertEqual(parser_output.get("registrant_city"), "Mountain View")

    def test_tld_nu(self):
        query_output = self.get_txt("nu")
        tld = "nu"
        parser_output = self.parser.parse(query_output, tld)
        # confirm dates
        created_date = parser_output.get("created")
        self.assertEqual(created_date.year, 2011)
        self.assertEqual(created_date.month, 4)
        self.assertEqual(created_date.day, 15)
        updated_date = parser_output.get("updated")
        self.assertEqual(updated_date.year, 2021)
        self.assertEqual(updated_date.month, 2)
        self.assertEqual(updated_date.day, 16)
        expired_date = parser_output.get("expires")
        self.assertEqual(expired_date.year, 2022)
        self.assertEqual(expired_date.month, 4)
        self.assertEqual(expired_date.day, 15)
        # registrar
        self.assertEqual(parser_output.get("registrar"), "Domeneshop AS")
        self.assertEqual(parser_output.get("registrant_name"), "DNS1856879")
        self.assertEqual(len(parser_output.get("name_servers")), 3)
        self.assertEqual(len(parser_output.get("status")), 1)
        self.assertEqual(parser_output.get("dnssec"), "signed delegation")

    def test_tld_is(self):
        query_output = self.get_txt("is")
        tld = "is"
        parser_output = self.parser.parse(query_output, tld)
        # confirm dates
        created_date = parser_output.get("created")
        self.assertEqual(created_date.year, 2000)
        self.assertEqual(created_date.month, 1)
        self.assertEqual(created_date.day, 18)
        expired_date = parser_output.get("expires")
        self.assertEqual(expired_date.year, 2022)
        self.assertEqual(expired_date.month, 1)
        self.assertEqual(expired_date.day, 18)
        # registrar
        self.assertEqual(
            parser_output.get("registrant_name"), "Amazon Europe Core S.a.r.l."
        )
        self.assertEqual(
            parser_output.get("registrant_address"),
            "38 avenue John F. Kennedy, LU-L-1855 Luxembourg",
        )
        self.assertEqual(len(parser_output.get("name_servers")), 4)
        self.assertEqual(parser_output.get("dnssec"), "unsigned delegation")

    def test_tld_cr(self):
        query_output = self.get_txt("cr")
        tld = "cr"
        parser_output = self.parser.parse(query_output, tld)
        # confirm dates
        created_date = parser_output.get("created")
        self.assertEqual(created_date.year, 2008)
        self.assertEqual(created_date.month, 3)
        self.assertEqual(created_date.day, 23)
        updated_date = parser_output.get("updated")
        self.assertEqual(updated_date.year, 2021)
        self.assertEqual(updated_date.month, 2)
        self.assertEqual(updated_date.day, 5)
        expired_date = parser_output.get("expires")
        self.assertEqual(expired_date.year, 2022)
        self.assertEqual(expired_date.month, 3)
        self.assertEqual(expired_date.day, 24)
        # registrar
        self.assertEqual(parser_output.get("registrar"), "COMLAUDE")
        self.assertEqual(
            parser_output.get("registrant_name"), "Amazon Technologies, Inc."
        )
        self.assertEqual(
            parser_output.get("registrant_organization"),
            "Amazon Technologies, Inc.",
        )
        self.assertEqual(
            parser_output.get("registrant_address"),
            "P.O. Box 8102, Reno, 89507, Nevada, US",
        )
        self.assertEqual(len(parser_output.get("name_servers")), 9)

    def test_tld_cz(self):
        query_output = self.get_txt("cz")
        tld = "cz"
        parser_output = self.parser.parse(query_output, tld)
        # confirm dates
        created_date = parser_output.get("created")
        self.assertEqual(created_date.year, 1997)
        self.assertEqual(created_date.month, 9)
        self.assertEqual(created_date.day, 19)
        expired_date = parser_output.get("expires")
        self.assertEqual(expired_date.year, 2021)
        self.assertEqual(expired_date.month, 10)
        self.assertEqual(expired_date.day, 28)
        updated_date = parser_output.get("updated")
        self.assertEqual(updated_date.year, 2017)
        self.assertEqual(updated_date.month, 1)
        self.assertEqual(updated_date.day, 12)
        # registrar
        self.assertEqual(parser_output.get("registrar"), "REG-NOMIQ")
        self.assertEqual(parser_output.get("registrant_name"), "Legal Department")
        self.assertEqual(
            parser_output.get("registrant_organization"),
            "Amazon Europe Holding Technologies SCS",
        )
        self.assertEqual(
            parser_output.get("registrant_address"),
            "65, boulevard Grande-Duchesse Charlotte, Luxembourg City, 1331, LU",
        )
        self.assertEqual(len(parser_output.get("name_servers")), 6)

    def test_tld_gg(self):
        query_output = self.get_txt("gg")
        tld = "gg"
        parser_output = self.parser.parse(query_output, tld)
        # confirm dates
        created_date = parser_output.get("created")
        self.assertEqual(created_date.year, 2003)
        self.assertEqual(created_date.month, 4)
        self.assertEqual(created_date.day, 30)
        # registrant
        self.assertEqual(parser_output.get("registrant_name"), "Google LLC")
        # registrar
        self.assertEqual(
            parser_output.get("registrar"),
            "MarkMonitor Inc. (http://www.markmonitor.com)",
        )
        # name servers and status
        self.assertEqual(len(parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser_output.get("status")), 4)

    def test_tld_ge(self):
        query_output = self.get_txt("ge")
        tld = "ge"
        parser_output = self.parser.parse(query_output, tld)
        # confirm dates
        created_date = parser_output.get("created")
        self.assertEqual(created_date.year, 2006)
        self.assertEqual(created_date.month, 7)
        self.assertEqual(created_date.day, 28)
        expired_date = parser_output.get("expires")
        self.assertEqual(expired_date.year, 2021)
        self.assertEqual(expired_date.month, 7)
        self.assertEqual(expired_date.day, 29)
        # registrant
        self.assertEqual(parser_output.get("registrant_name"), "Google LLC")
        # registrar
        self.assertEqual(parser_output.get("registrar"), "proservice ltd")
        # misc
        self.assertEqual(len(parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser_output.get("status")), 1)

    def test_tld_jp(self):
        query_output = self.get_txt("jp")
        tld = "jp"
        parser_output = self.parser.parse(query_output, tld)
        # confirm dates
        created_date = parser_output.get("created")
        self.assertEqual(created_date.year, 2010)
        self.assertEqual(created_date.month, 9)
        self.assertEqual(created_date.day, 22)
        #
        expires_date = parser_output.get("expires")
        self.assertEqual(expires_date.year, 2021)
        self.assertEqual(expires_date.month, 9)
        self.assertEqual(expires_date.day, 30)
        # registrant
        self.assertEqual(parser_output.get("registrant_name"), "Amazon, Inc.")
        # address
        self.assertEqual(
            parser_output.get("registrant_address"),
            "Meguro-ku, Arco Tower Annex, 8-1, Shimomeguro 1-chome",
        )
        # name servers
        self.assertEqual(len(parser_output.get("name_servers")), 8)

    def test_tld_ax(self):
        query_output = self.get_txt("ax")
        tld = "ax"
        parser_output = self.parser.parse(query_output, tld)
        # confirm dates
        created_date = parser_output.get("created")
        self.assertEqual(created_date.year, 2016)
        self.assertEqual(created_date.month, 9)
        self.assertEqual(created_date.day, 8)
        expired_date = parser_output.get("expires")
        self.assertEqual(expired_date.year, 2021)
        self.assertEqual(expired_date.month, 9)
        self.assertEqual(expired_date.day, 8)
        updated_date = parser_output.get("updated")
        self.assertEqual(updated_date.year, 2020)
        self.assertEqual(updated_date.month, 9)
        self.assertEqual(updated_date.day, 5)
        # registrant
        self.assertEqual(parser_output.get("registrant_name"), "xTom GmbH")
        self.assertEqual(parser_output.get("registrant_country"), "Tyskland")
        self.assertEqual(
            parser_output.get("registrant_address"),
            "Kreuzstr.60, 40210, Duesseldorf",
        )
        # registrar
        self.assertEqual(parser_output.get("registrar"), "xTom")
        self.assertEqual(parser_output.get("registrar_url"), "https://xtom.com/")
        # misc
        self.assertEqual(len(parser_output.get("name_servers")), 2)
        self.assertEqual(len(parser_output.get("status")), 1)
        self.assertEqual(parser_output.get("domain_name"), "google.ax")

    def test_tld_aw(self):
        query_output = self.get_txt("aw")
        tld = "aw"
        parser_output = self.parser.parse(query_output, tld)
        # confirm dates
        created_date = parser_output.get("created")
        self.assertEqual(created_date.year, 2017)
        self.assertEqual(created_date.month, 9)
        self.assertEqual(created_date.day, 13)
        updated_date = parser_output.get("updated")
        self.assertEqual(updated_date.year, 2018)
        self.assertEqual(updated_date.month, 5)
        self.assertEqual(updated_date.day, 21)
        # registrar
        self.assertEqual(parser_output.get("registrar"), "SETAR N.V.")
        # misc
        self.assertEqual(parser_output.get("dnssec"), "no")
        self.assertEqual(len(parser_output.get("name_servers")), 4)
        self.assertEqual(len(parser_output.get("status")), 1)
        self.assertEqual(parser_output.get("domain_name"), "google.aw")
