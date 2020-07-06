import unittest

from asyncwhois.query import WhoIsQuery


class TestWhoIsQuery(unittest.TestCase):

    def test_query_com(self):
        query = WhoIsQuery("google.com")
        self.assertIn("domain name: google.com", query.query_output.lower())

    def test_query_net(self):
        query = WhoIsQuery("comcast.net")
        self.assertIn("domain name: comcast.net", query.query_output.lower())

    def test_query_top(self):
        query = WhoIsQuery("com-wu.top")
        self.assertIn("domain name: com-wu.top", query.query_output.lower())

    def test_query_info(self):
        query = WhoIsQuery("public.info")
        self.assertIn("domain name: public.info", query.query_output.lower())

    def test_query_io(self):
        query = WhoIsQuery("phishery.io")
        self.assertIn("domain name: phishery.io", query.query_output.lower())

    def test_query_co(self):
        query = WhoIsQuery("elastic.co")
        self.assertIn("domain name: elastic.co", query.query_output.lower())

    def test_query_xyz(self):
        query = WhoIsQuery("abc.xyz")
        self.assertIn("domain name: abc.xyz", query.query_output.lower())

    def test_query_org(self):
        query = WhoIsQuery("vote.org")
        self.assertIn("domain name: vote.org", query.query_output.lower())
