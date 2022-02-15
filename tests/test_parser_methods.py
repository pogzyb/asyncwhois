import unittest
import datetime

from asyncwhois.parse import BaseParser


class TestWhoIsParserMethods(unittest.TestCase):

    def test_parse_dates(self):
        date_strings = [
            '11-aug-2020',
            '11-August-2020',
            '11-09-2020',
            '2020-09-20',
            '2020.09.20',
            '2020/09/20',
            '2020. 09. 20.',
            '2020.09.20 11:11:11',
            'August 11 2020',
            '20200920'
        ]

        for date_string in date_strings:
            formatted_date = BaseParser._parse_date(date_string)
            self.assertIsInstance(formatted_date, datetime.datetime)

    def test_find_match(self):
        test_blob = """
        Domain name: google.com
        Name server: ns1.google.com
        Name server: ns2.google.com
        Status: ok
        """
        domain = BaseParser().find_match(r'domain name: *(.+)', test_blob)
        self.assertEqual(domain, "google.com")
        name_servers = BaseParser().find_match(r'name server: *(.+)', test_blob, many=True)
        self.assertEqual(len(name_servers), 2)
        status = BaseParser().find_match(r'status: *(.+)', test_blob, many=True)
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
        name_servers = BaseParser().find_multiline_match(r'Domain nameservers:\n', test_blob)
        self.assertEqual(len(name_servers), 4)
