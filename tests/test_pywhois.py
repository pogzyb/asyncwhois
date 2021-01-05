import asynctest
import asynctest.mock as mock

import asyncwhois
from asyncwhois.pywhois import PyWhoIs
from asyncwhois.errors import WhoIsQueryConnectError


class TestPyWhoIs(asynctest.TestCase):

    def setUp(self) -> None:
        self.test_ip = '8.8.8.8'
        self.fake_domain = "some-domain-somewhere-out-there.co.uk"
        self.fake_query_result = "Domain Name: some-domain-somewhere-out-there.co.uk"

    def test_get_tld_extract(self):
        pyw = PyWhoIs()
        assert pyw._get_tld_extract('https://www.microsoft.com').suffix == 'com'
        assert pyw._get_tld_extract('https://www.wikipedia.org').suffix == 'org'
        assert pyw._get_tld_extract('https://www.coral.ai').suffix == 'ai'

    def test_get_hostname_from_ip(self):
        pyw = PyWhoIs()
        assert pyw._get_hostname_from_ip(self.test_ip) == 'dns.google'
        self.assertRaises(WhoIsQueryConnectError, pyw._get_hostname_from_ip('0.0.0.0'))

    async def test_aio_get_hostname_from_ip(self):
        pyw = PyWhoIs()
        assert await pyw._aio_get_hostname_from_ip(self.test_ip) == 'dns.google'
        self.assertAsyncRaises(WhoIsQueryConnectError, pyw._aio_get_hostname_from_ip('0.0.0.0'))

    @mock.patch('asyncwhois.query.WhoIsQuery._run')
    def test_from_url(self, mock_run):
        pyw = PyWhoIs._from_url('some-domain-somewhere-out-there.co.uk', timeout=10)
        mock_run.assert_called_once()
        self.assertIsNotNone(pyw.query_output)
        self.assertIsNotNone(pyw.parser_output)

    @mock.patch('asyncwhois.query.AsyncWhoIsQuery.create')
    async def test_aio_from_url(self, mock_run):
        mock_run.return_value = mock.Mock(query_output="Domain Name: some-domain-somewhere-out-there.co.uk")
        pyw = await PyWhoIs._aio_from_url('some-domain-somewhere-out-there.co.uk', timeout=10)
        mock_run.assert_called_once()
        self.assertIsNotNone(pyw.query_output)
        self.assertIsNotNone(pyw.parser_output)

    @mock.patch('subprocess.Popen')
    def test_from_whois_cmd(self, mock_proc):
        mock_communicate_method = mock.Mock(communicate=mock.Mock(
            return_value=(self.fake_query_result.encode(), None)))
        mock_proc.return_value = mock_communicate_method
        pyw = PyWhoIs._from_whois_cmd(self.test_ip, timeout=10)
        mock_proc.assert_called_once()
        self.assertIsNotNone(pyw.query_output)
        self.assertIsNotNone(pyw.parser_output)

    @mock.patch('asyncio.create_subprocess_shell')
    async def test_aio_from_whois_cmd(self, mock_proc):
        mock_communicate_method = mock.CoroutineMock(communicate=mock.CoroutineMock(
            return_value=(self.fake_query_result.encode(), None)))
        mock_proc.return_value = mock_communicate_method
        pyw = await PyWhoIs._aio_from_whois_cmd(self.test_ip, timeout=10)
        mock_proc.assert_called_once()
        self.assertIsNotNone(pyw.query_output)
        self.assertIsNotNone(pyw.parser_output)