import asynctest

from asyncwhois.query import AsyncWhoIsQuery


class TestAsyncWhoIsQuery(asynctest.TestCase):

    async def test_query_com(self):
        query = await AsyncWhoIsQuery.create("google.com")
        self.assertIn("domain name: google.com\n", query.query_output.lower())

    async def test_query_net(self):
        query = await AsyncWhoIsQuery.create("comcast.net")
        self.assertIn("domain name: comcast.net\n", query.query_output.lower())

    async def test_query_top(self):
        query = await AsyncWhoIsQuery.create("com-wu.top")
        self.assertIn("domain name: com-wu.top\n", query.query_output.lower())

    async def test_query_info(self):
        query = await AsyncWhoIsQuery.create("business.info")
        self.assertIn("domain name: business.info\n", query.query_output.lower())
