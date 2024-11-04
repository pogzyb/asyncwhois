import unittest
import datetime
import json
import os

from asyncwhois.parse import BaseParser, convert_whodap_keys


class TestWhoIsParserMethods(unittest.TestCase):
    def test_convert_whodap_keys(self):
        with open(
            os.path.join(
                os.path.abspath(os.path.dirname(__file__)),
                "samples/com_dict_asyncwhois.json",
            )
        ) as o:
            asyncwhois_dict = json.loads(o.read())

        with open(
            os.path.join(
                os.path.abspath(os.path.dirname(__file__)),
                "samples/com_dict_whodap.json",
            )
        ) as o:
            whodap_dict = json.loads(o.read())

        whodap_keys_after = convert_whodap_keys(whodap_dict).keys()
        asyncwhois_keys = asyncwhois_dict.keys()
        for whodap_key in whodap_keys_after:
            assert (
                whodap_key in asyncwhois_keys
            ), f"{whodap_key} not in {asyncwhois_keys}"

        for asyncwhois_key in asyncwhois_dict.keys():
            assert (
                asyncwhois_key in whodap_keys_after
            ), f"{asyncwhois_key} not in {whodap_keys_after}"

    def test_parse_dates(self):
        date_strings = [
            "11-aug-2020",
            "11-August-2020",
            "11-09-2020",
            "2020-09-20",
            "2020.09.20",
            "2020/09/20",
            "2020. 09. 20.",
            "2020.09.20 11:11:11",
            "August 11 2020",
            "20200920",
        ]

        for date_string in date_strings:
            formatted_date = BaseParser()._parse_date(date_string)
            self.assertIsInstance(formatted_date, datetime.datetime)

    def test_find_match(self):
        test_blob = """
        Domain name: google.com
        Name server: ns1.google.com
        Name server: ns2.google.com
        Status: ok
        """
        domain = BaseParser().find_match(r"domain name: *(.+)", test_blob)
        self.assertEqual(domain, "google.com")
        name_servers = BaseParser().find_match(
            r"name server: *(.+)", test_blob, many=True
        )
        self.assertEqual(len(name_servers), 2)
        status = BaseParser().find_match(r"status: *(.+)", test_blob, many=True)
        self.assertEqual(len(status), 1)

    def test_find_multiline_match(self):
        test_blob = """
        Domain name: google.com
        
        Domain nameservers:
           ns1.googledomains.com
           ns2.googledomains.com
           ns3.googledomains.com
           ns4.googledomains.com

        Registrar: someone
        """
        name_servers = BaseParser().find_multiline_match(
            r"Domain nameservers:\n", test_blob
        )
        self.assertEqual(len(name_servers), 4)
