import unittest
import os

from asyncwhois.parser import WhoIsParser


class TestWhoIsParser(unittest.TestCase):

    def test_parser_com(self):
        with open(os.path.join(os.getcwd(), "samples/tld_com.txt")) as txt_input:
            query_output = txt_input.read()
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
        with open(os.path.join(os.getcwd(), "samples/tld_in.txt")) as txt_input:
            query_output = txt_input.read()
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
        with open(os.path.join(os.getcwd(), "samples/tld_top.txt")) as txt_input:
            query_output = txt_input.read()
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
        with open(os.path.join(os.getcwd(), "samples/tld_xyz.txt")) as txt_input:
            query_output = txt_input.read()
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
        with open(os.path.join(os.getcwd(), "samples/tld_ir.txt")) as txt_input:
            query_output = txt_input.read()
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
        self.assertEqual(parser.parser_output.get("registrant_state"), None)
        self.assertEqual(parser.parser_output.get("registrant_country"), None)
        self.assertEqual(parser.parser_output.get("registrant_zipcode"), None)
        self.assertEqual(parser.parser_output.get("registrant_address"), "1600 Amphitheatre Parkway, Mountain View, CA, US")
        # registrar
        self.assertEqual(parser.parser_output.get("registrar"), None)
        # registrant
        self.assertEqual(parser.parser_output.get("registrant_organization"), "Google Inc.")
        self.assertEqual(parser.parser_output.get("registrant_name"), "(Domain Holder) Google Inc.")


    def test_parser_icu(self):
        with open(os.path.join(os.getcwd(), "samples/tld_icu.txt")) as txt_input:
            query_output = txt_input.read()
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


