import unittest
import os

from asyncwhois.parser import WhoIsParser


class TestWhoIsParser(unittest.TestCase):

    def test_parser_com(self):
        with open(os.path.join(os.getcwd(), "samples/tld_com.txt")) as txt_input:
            query_output = txt_input.read()
        parser = WhoIsParser('com')
        parser.parse(query_output)
        self.assertEqual(parser.parser_output.get("created"), "1997-09-15")
        self.assertEqual(parser.parser_output.get("updated"), "2019-09-09")
        self.assertEqual(parser.parser_output.get("expires"), "2028-09-14")

    def test_parser_in(self):
        with open(os.path.join(os.getcwd(), "samples/tld_in.txt")) as txt_input:
            query_output = txt_input.read()
        parser = WhoIsParser('in')
        parser.parse(query_output)
        self.assertEqual(parser.parser_output.get("created"), "2007-12-01")
        self.assertEqual(parser.parser_output.get("updated"), "2019-12-01")
        self.assertEqual(parser.parser_output.get("expires"), "2020-12-01")
        self.assertEqual(parser.parser_output.get("state"), "Rajasthan")
        self.assertEqual(parser.parser_output.get("country"), "IN")

    def test_parser_top(self):
        with open(os.path.join(os.getcwd(), "samples/tld_top.txt")) as txt_input:
            query_output = txt_input.read()
        parser = WhoIsParser('top')
        parser.parse(query_output)
        self.assertEqual(parser.parser_output.get("created"), "2020-02-25")
        self.assertEqual(parser.parser_output.get("updated"), "2020-05-22")
        self.assertEqual(parser.parser_output.get("expires"), "2021-02-25")
        self.assertEqual(parser.parser_output.get("state"), "AZ")
        self.assertEqual(parser.parser_output.get("country"), "US")
        self.assertEqual(parser.parser_output.get("zipcode"), "85016")

    def test_parser_xyz(self):
        with open(os.path.join(os.getcwd(), "samples/tld_xyz.txt")) as txt_input:
            query_output = txt_input.read()
        parser = WhoIsParser('xyz')
        parser.parse(query_output)
        self.assertEqual(parser.parser_output.get("created"), "2019-10-15")
        self.assertEqual(parser.parser_output.get("updated"), "0001-01-01")
        self.assertEqual(parser.parser_output.get("expires"), "2020-10-15")
        self.assertEqual(parser.parser_output.get("state"), "Panama")
        self.assertEqual(parser.parser_output.get("country"), "PA")
        self.assertEqual(parser.parser_output.get("zipcode"), None)

    def test_parser_ir(self):
        with open(os.path.join(os.getcwd(), "samples/tld_ir.txt")) as txt_input:
            query_output = txt_input.read()
        parser = WhoIsParser('ir')
        parser.parse(query_output)
        self.assertEqual(parser.parser_output.get("created"), None)
        self.assertEqual(parser.parser_output.get("updated"), "2019-11-07")
        self.assertEqual(parser.parser_output.get("expires"), "2020-12-22")
        self.assertEqual(parser.parser_output.get("state"), None)
        self.assertEqual(parser.parser_output.get("country"), None)
        self.assertEqual(parser.parser_output.get("zipcode"), None)

    def test_parser_icu(self):
        with open(os.path.join(os.getcwd(), "samples/tld_icu.txt")) as txt_input:
            query_output = txt_input.read()
        parser = WhoIsParser('icu')
        parser.parse(query_output)
        self.assertEqual(parser.parser_output.get("created"), "2019-05-11")
        self.assertEqual(parser.parser_output.get("updated"), "2019-10-23")
        self.assertEqual(parser.parser_output.get("expires"), "2020-05-11")
        self.assertEqual(parser.parser_output.get("state"), "Sind(en)")
        self.assertEqual(parser.parser_output.get("country"), "PK")
        self.assertEqual(parser.parser_output.get("city"), "karachi")
        self.assertEqual(parser.parser_output.get("zipcode"), "75640")

