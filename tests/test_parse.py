import os

import asynctest

from asyncwhois import WhoisEntry


class TestParseWhoIsText(asynctest.TestCase):

    def setUp(self):
        self.base_path = '/Users/josepho/Desktop/py-practice/async-pywhois/tests/samples/'

    def test_parse_top(self):
        domain = 'com-wu.top'
        with open(os.path.join(self.base_path, 'tld_top.txt'), 'r') as topfile: 
            text = topfile.read()
        top = WhoisEntry.load(domain, text)
        print(top)

    # def test_parse_ir(self):
    #     domain = 'masoudrahimi.ir'
    #     with open(os.path.join(self.base_path, 'tld_ir.txt'), 'r') as topfile: 
    #         text = topfile.read()
    #     ir = WhoisEntry.load(domain, text)
    #     print(ir)

    # def test_parse_xyz(self):
    #     domain = 'redemtoin.xyz'
    #     with open(os.path.join(self.base_path, 'tld_xyz.txt'), 'r') as topfile: 
    #         text = topfile.read()
    #     xyz = WhoisEntry.load(domain, text)
    #     print(xyz)

    # def test_parse_icu(self):
    #     domain = 'skyline-empire.icu'
    #     with open(os.path.join(self.base_path, 'tld_icu.txt'), 'r') as topfile: 
    #         text = topfile.read()
    #     icu = WhoisEntry.load(domain, text)
    #     print(icu)
