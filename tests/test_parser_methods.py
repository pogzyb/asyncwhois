import unittest
import datetime

from asyncwhois.parser import WhoIsParser, BaseParser


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