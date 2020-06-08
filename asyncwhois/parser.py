from typing import Dict, Any, Union, List
import datetime
import re

from .errors import WhoIsQueryError

# Date formats from richardpenman/pywhois
KNOWN_DATE_FORMATS = [
    '%d-%b-%Y',                 # 02-jan-2000
    '%d-%B-%Y',                 # 11-February-2000
    '%d-%m-%Y',                 # 20-10-2000
    '%Y-%m-%d',                 # 2000-01-02
    '%d.%m.%Y',                 # 2.1.2000
    '%Y.%m.%d',                 # 2000.01.02
    '%Y/%m/%d',                 # 2000/01/02
    '%Y%m%d',                   # 20170209
    '%d/%m/%Y',                 # 02/01/2013
    '%Y. %m. %d.',              # 2000. 01. 02.
    '%Y.%m.%d %H:%M:%S',        # 2014.03.08 10:28:24
    '%d-%b-%Y %H:%M:%S %Z',     # 24-Jul-2009 13:20:03 UTC
    '%a %b %d %H:%M:%S %Z %Y',  # Tue Jun 21 23:59:59 GMT 2011
    '%Y-%m-%dT%H:%M:%SZ',       # 2007-01-26T19:10:31Z
    '%Y-%m-%dT%H:%M:%S.%fZ',    # 2018-12-01T16:17:30.568Z
    '%Y-%m-%dT%H:%M:%S%z',      # 2013-12-06T08:17:22-0800
    '%Y-%m-%d %H:%M:%SZ',       # 2000-08-22 18:55:20Z
    '%Y-%m-%d %H:%M:%S',        # 2000-08-22 18:55:20
    '%d %b %Y %H:%M:%S',        # 08 Apr 2013 05:44:00
    '%d/%m/%Y %H:%M:%S',        # 23/04/2015 12:00:07 EEST
    '%d/%m/%Y %H:%M:%S %Z',     # 23/04/2015 12:00:07 EEST
    '%d/%m/%Y %H:%M:%S.%f %Z',  # 23/04/2015 12:00:07.619546 EEST
    '%B %d %Y',                 # August 14 2017
    '%d.%m.%Y %H:%M:%S',        # 08.03.2014 10:28:24
]


class BaseParser:

    base_expressions = {
        'domain_name': 'Domain Name: *(.+)',
        'created': r'Creation Date: (\d{4}-\d{2}-\d{2})',
        'updated': r'Updated Date: (\d{4}-\d{2}-\d{2})',
        'expires': r'Registry Expiry Date: (\d{4}-\d{2}-\d{2})',
        'registrar': r'Registrar: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_organization': r'Registrant Organization: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'registrant_zipcode': r'Registrant Postal Code: *(.+)',
        'registrant_address': r'Registrant Street: *(.+)',
        'registrant_city': r'Registrant City: *(.+)',
        'registrant_state': r'Registrant State/Province: *(.+)',
        'dnssec': r'DNSSEC: *([\S]+)',
        'status': r'Status: *(.+)',
        'name_servers': r'Name server: *(.+)'
    }

    def __init__(self):
        self.server = None
        self.reg_expressions = {}

    def update_reg_expressions(self, expressions_update: Dict[str, Any]) -> None:
        expressions = self.base_expressions.copy()
        expressions.update(expressions_update)
        self.reg_expressions = expressions

    def parse(self, blob: str) -> Dict[str, Any]:
        parsed = {}
        list_keys = ['status', 'name_servers']
        date_keys = ['created', 'updated', 'expires']
        for key, regex in self.reg_expressions.items():
            if not regex:
                parsed[key] = None
            else:
                many = key in list_keys
                parsed[key] = self._find_match(regex, blob, many)
                if key in date_keys and parsed.get(key, None):
                    parsed[key] = self._parse_date(parsed.get(key))
        return parsed

    def _parse_date(self, date_string: str) -> Union[datetime.date, str]:
        for date_format in KNOWN_DATE_FORMATS:
            try:
                date = datetime.datetime.strptime(date_string, date_format)
                return date
            except ValueError:
                continue
        return date_string

    def _find_match(self, regex: str, blob: str, many: bool = False) -> Union[str, List[str], None]:
        if many:
            matches = re.findall(regex, blob, flags=re.IGNORECASE)
            return [m.rstrip('\r').lstrip('\t') for m in matches]
        else:
            match = re.search(regex, blob, flags=re.IGNORECASE)
            if match:
                return match.group(1).rstrip('\r').lstrip('\t')
            return None


class WhoIsParser:

    def __init__(self, top_level_domain: str):
        self.parser_output = {}
        self._parser = self._init_parser(top_level_domain)

    def parse(self, blob: str) -> None:
        no_match_checks = ['no match', 'not found']
        if any([n in blob.lower() for n in no_match_checks]):
            raise WhoIsQueryError(f'Domain not found!')
        self.parser_output = self._parser.parse(blob)

    @staticmethod
    def _init_parser(tld: str) -> BaseParser:
        if tld == 'ae':
            return RegexAE()
        elif tld == 'ai':
            return RegexAI()
        elif tld == 'app':
            return RegexAPP()
        elif tld == 'ar':
            return RegexAR()
        elif tld == 'at':
            return RegexAT()
        elif tld == 'au':
            return RegexAU()
        elif tld == 'be':
            return RegexBE()
        elif tld == 'biz':
            return RegexBIZ()
        elif tld == 'br':
            return RegexBR()
        elif tld == 'by':
            return RegexBY()
        elif tld == 'ca':
            return RegexCA()
        elif tld == 'cat':
            return RegexCAT()
        elif tld == 'ch':
            return RegexCH()
        elif tld == 'co':
            return RegexCO()
        elif tld == 'com':
            return RegexCOM()
        elif tld == 'cl':
            return RegexCL()
        elif tld == 'club':
            return RegexClub()
        elif tld == 'cn':
            return RegexCN()
        elif tld == 'cr':
            return RegexCR()
        elif tld == 'cz':
            return RegexCZ()
        elif tld == 'de':
            return RegexDE()
        elif tld == 'dk':
            return RegexDK()
        elif tld == 'do':
            return RegexDO()
        elif tld == 'ee':
            return RegexEE()
        elif tld == 'eu':
            return RegexEU()
        elif tld == 'fr':
            return RegexFR()
        elif tld == 'hk':
            return RegexHK()
        elif tld == 'hn':
            return RegexHN()
        elif tld == 'hr':
            return RegexHR()
        elif tld == 'icu':
            return RegexICU()
        elif tld == 'id':
            return RegexID()
        elif tld == 'ie':
            return RegexIE()
        elif tld == 'il':
            return RegexIL()
        elif tld == 'in':
            return RegexIN()
        elif tld == 'info':
            return RegexINFO()
        elif tld == 'io':
            return RegexIO()
        elif tld == 'ir':
            return RegexIR()
        elif tld == 'is':
            return RegexIS()
        elif tld == 'it':
            return RegexIT()
        elif tld == 'jobs':
            return RegexJobs()
        elif tld == 'jp':
            return RegexJP()
        elif tld == 'kg':
            return RegexKG()
        elif tld == 'kr':
            return RegexKR()
        elif tld == 'kz':
            return RegexKZ()
        elif tld == 'lat':
            return RegexLAT()
        elif tld == 'li':
            return RegexLI()
        elif tld == 'lu':
            return RegexLU()
        elif tld == 'me':
            return RegexME()
        elif tld == 'mobi':
            return RegexMOBI()
        elif tld == 'money':
            return RegexMONEY()
        elif tld == 'mx':
            return RegexMX()
        elif tld == 'name':
            return RegexNAME()
        elif tld == 'net':
            return RegexNET()
        elif tld == 'no':
            return RegexNO()
        elif tld == 'nz':
            return RegexNZ()
        elif tld == 'online':
            return RegexONLINE()
        elif tld == 'org':
            return RegexORG()
        elif tld == 'pe':
            return RegexPE()
        elif tld == 'pl':
            return RegexPL()
        elif tld == 'rf':
            return RegexRF()
        elif tld == 'ro':
            return RegexRO()
        elif tld == 'ru':
            return RegexRU()
        elif tld == 'space':
            return RegexSPACE()
        elif tld == 'top':
            return RegexTOP()
        elif tld == 'tr':
            return RegexTR()
        elif tld == 'tw':
            return RegexTW()
        elif tld == 'ua':
            return RegexUA()
        elif tld == 'uk':
            return RegexUK()
        elif tld == 'us':
            return RegexUS()
        elif tld == 've':
            return RegexVE()
        elif tld =='xyz':
            return RegexXYZ()

        else:
            return BaseParser()


# ==============================
# WhoIs Query Output Parsers
# ==============================


class RegexCOM(BaseParser):

    _com_expressions = {
        'expires': r'Registrar Registration Expiration Date: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.verisign-grs.com'
        self.update_reg_expressions(self._com_expressions)


class RegexNET(BaseParser):

    _net_expressions = {
        'expires': r'Registrar Registration Expiration Date: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.verisign-grs.com'
        self.update_reg_expressions(self._net_expressions)


class RegexORG(BaseParser):

    _org_expressions = {
        'expires': r'Registrar Registration Expiration Date: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.pir.org'
        self.update_reg_expressions(self._org_expressions)


class RegexRU(BaseParser):

    _ru_expressions = {
        'created': r'created: *(.+)',
        'expires': r'paid-till: *(.+)',
        'registrant_organization': r'org: *(.+)',
        'status': r'state: *(.+)',
        'name_servers': r'nserver: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.tcinet.ru'
        self.update_reg_expressions(self._ru_expressions)


class RegexCL(BaseParser):

    _cl_expressions = {
        'name_servers': r'Name server: *(.+)',
        'registrant_name': r'Registrant name: *(.+)',
        'registrant_organization': r'Registrant organisation: *(.+)',
        'registrar': r'Registrar name: *(.+)',
        'expires': r'Expiration date: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.cl'
        self.update_reg_expressions(self._cl_expressions)


class RegexCO(BaseParser):

    _co_expressions = {
        'expires': r'Registrar Registration Expiration Date: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.co'
        self.update_reg_expressions(self._co_expressions)


class RegexPL(BaseParser):

    _pl_expressions = {
        'domain_name': r'DOMAIN NAME: *(.+)\n',
        'name_servers': r'nameservers:((?:\s+.+\n+)*)',
        'registrar': r'REGISTRAR:\s*(.+)',
        'created': r'(?<! )created: *(.+)\n',
        'expires': r'renewal date: *(.+)',
        'updated': r'last modified: *(.+)\n',
        'dnssec': r'dnssec: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.dns.pl'
        self.update_reg_expressions(self._pl_expressions)


class RegexRO(BaseParser):
    # % The ROTLD WHOIS service on port 43 never discloses any information concerning the registrant.

    _ro_expressions = {
        'created': r'Registered On: *(.+)',
        'expires': r'Expires On: *(.+)',
        'name_servers': r'Nameserver: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.rotld.ro'
        self.update_reg_expressions(self._ro_expressions)


class RegexPE(BaseParser):

    _pe_expressions = {
        'registrant_name': r'Registrant name: *(.+)',
        'registrar': r'Sponsoring Registrar: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'name_servers': r'Name server: *(.+)',
        'status': r'Domain Status: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'kero.yachay.pe'
        self.update_reg_expressions(self._pe_expressions)


class RegexSPACE(BaseParser):

    _space_expressions = {
        'expires': r'Registrar Registration Expiration Date: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.space'
        self.update_reg_expressions(self._space_expressions)


class RegexNAME(BaseParser):

    _name_expressions = {}

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.name'
        self.update_reg_expressions(self._name_expressions)


class RegexME(BaseParser):

    _me_expressions = {}

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.me'
        self.update_reg_expressions(self._me_expressions)


class RegexUS(BaseParser):

    _us_expressions = {}

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.us'
        self.update_reg_expressions(self._us_expressions)


class RegexEE(BaseParser):

    _ee_expressions = {
        'domain_name': r'Domain: *[\n\r]+\s*name: *([^\n\r]+)',
        'status': r'status: *([^\n\r]+)',
        'created': r'registered: *([^\n\r]+)',
        'updated': r'changed: *([^\n\r]+)',
        'expires': r'expire: *([^\n\r]+)',
        'registrar': r'Registrar: *[\n\r]+\s*name: *([^\n\r]+)',
        'name_servers': r'nserver: *(.*)',
        'country': r'country: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.tld.ee'
        self.update_reg_expressions(self._ee_expressions)


class RegexCA(BaseParser):

    _ca_expressions = {}

    def __init__(self):
        super().__init__()
        self.server = 'whois.cira.ca'
        self.update_reg_expressions(self._ca_expressions)


class RegexFR(BaseParser):

    _fr_expressions = {
        'created': r'created: (\d{4}-\d{2}-\d{2})',
        'updated': r'last-update: (\d{4}-\d{2}-\d{2})',
        'expires': r'Expiry Date: (\d{4}-\d{2}-\d{2})',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.fr'
        self.update_reg_expressions(self._fr_expressions)


class RegexBR(BaseParser):

    _br_expressions = {
        'created': r'created: ',
        'updated': r'changed: ',
        'status': r'status: *(.+)',
        'registrant_name': r'responsible: *(.+)',
        'registrant_country': r'country: *(.+)',
        'expires':  r'expires: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.registro.br'
        self.update_reg_expressions(self._br_expressions)


class RegexKR(BaseParser):

    _kr_expressions = {
        'created': r'Registered Date *: (\d{4}\.\s\d{2}\.\s\d{2}\.)',
        'updated': r'Last Updated Date *: (\d{4}\.\s\d{2}\.\s\d{2}\.)',
        'expires': r'Expiration Date *: (\d{4}\.\s\d{2}\.\s\d{2}\.)',
        'registrant_name': r'Registrant *: (.+)',
        'dnssec': r'DNSSEC *: (.+)',
        'registrant_zipcode': r'Registrant Zip Code: *: (.+)',
        'registrant_address': r'Registrant Address *: (.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.kr'
        self.update_reg_expressions(self._kr_expressions)


class RegexEU(BaseParser):
    # .EU whois server disclaimer:
    # % The EURid WHOIS service on port 43 (textual whois) never
    # % discloses any information concerning the registrant.

    _eu_expressions = {
        "registrar": r"Registrar:\nName: *(.+)",
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.eu'
        self.update_reg_expressions(self._eu_expressions)


class RegexDE(BaseParser):
    """
    .de disclaimer (very hard to extract information from this provider):

    % The DENIC whois service on port 43 doesn't disclose any information concerning
    % the domain holder, general request and abuse contact.
    % This information can be obtained through use of our web-based whois service
    % available at the DENIC website:
    % http://www.denic.de/en/domains/whois-service/web-whois.html

    """

    _de_expressions = {
        'updated': r'Changed: (\d{4}\.\s\d{2}\.\s\d{2}\.)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.denic.de'
        self.update_reg_expressions(self._de_expressions)


class RegexUK(BaseParser):

    _uk_expressions = {
        'created': r'Registered on: (\d{2}-\w{3}-\d{4})',
        'updated': r'Last updated: (\d{2}-\w{3}-\d{4})',
        'expires': r'Expiry date: (\d{2}-\w{3}-\d{4})',
        'registrar': r'Registrar:\s *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.uk'
        self.update_reg_expressions(self._uk_expressions)


class RegexJP(BaseParser):

    _jp_expressions = {
        'registrant_name': r'\[Registrant\] *(.+)',
        'created': r'\[登録年月日\] *(.+)',
        'expires': r'\[有効期限\] *(.+)',
        'status': r'\[状態\] *(.+)',
        'updated': r'\[最終更新\] *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.jprs.jp'
        self.update_reg_expressions(self._jp_expressions)


class RegexAU(BaseParser):

    _au_expressions = {
        'updated': r'Last Modified: (\d{2}-\w{3}-\d{4})',
        'registrar': r'Registrar Name:\s *(.+)',
        'registrant_name': r'Registrant: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.auda.org.au'
        self.update_reg_expressions(self._au_expressions)



class RegexAT(BaseParser):

    _at_expressions = {
        'registrar': r'registrar: *(.+)',
        'registrant_name': r'personname: *(.+)',
        'registrant_address': r'street address: *(.+)',
        'registrant_zipcode': r'postal code: *(.+)',
        'registrant_city': r'city: *(.+)',
        'registrant_country': r'country: *(.+)',
        'updated': r'changed: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.at'
        self.update_reg_expressions(self._at_expressions)


class RegexBE(BaseParser):

    _be_expressions = {
        'registrant_name': r'Name: *(.+)',
        'created': r'Registered: *(.+)',
        'registrar': r'Registrar:\nName: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.dns.be'
        self.update_reg_expressions(self._be_expressions)


class RegexINFO(BaseParser):

    _info_expressions = {
        'registrar':                   r'Registrar: *(.+)',
        'updated':                     r'Updated Date: *(.+)',
        'created':                     r'Creation Date: *(.+)',
        'expires':                     r'Registry Expiry Date: *(.+)',
        'status':                      r'Status: *(.+)',
        'registrant_name':             r'Registrant Name: *(.+)',
        'registrant_organization':     r'Registrant Organization: *(.+)',
        'registrant_address':          r'Registrant Street: *(.+)',
        'registrant_city':             r'Registrant City: *(.+)',
        'registrant_state':            r'Registrant State/Province: *(.+)',
        'registrant_zipcode':          r'Registrant Postal Code: *(.+)',
        'registrant_country':          r'Registrant Country: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.afilias.net'
        self.update_reg_expressions(self._info_expressions)


class RegexRF(BaseParser):  # same as RU

    def __init__(self):
        super().__init__()
        self.server = 'whois.tcinet.ru'
        self.update_reg_expressions(RegexRU._ru_expressions)


class RegexSU(BaseParser):  # same as RU

    def __init__(self):
        super().__init__()
        self.server = 'whois.tcinet.ru'
        self.update_reg_expressions(RegexRU._ru_expressions)


class RegexClub(BaseParser):

    _club_expressions = {
        'registrar': r'Sponsoring Registrar: *(.+)',
        'status': r'Domain Status: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_city':    r'Registrant City: *(.+)',
        'registrant_state':   r'Registrant State/Province: *(.+)',
        'registrant_zipcode': r'Registrant Postal Code: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'created': r'Domain Registration Date: *(.+)',
        'expires': r'Domain Expiration Date: *(.+)',
        'updated': r'Domain Last Updated Date: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.club'
        self.update_reg_expressions(self._club_expressions)


class RegexIO(BaseParser):

    _io_expressions = {
        'expires': r'Registrar Registration Expiration Date: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.io'
        self.update_reg_expressions(self._io_expressions)


class RegexBIZ(BaseParser):

    _biz_expressions = {
        'expires': r'Registrar Registration Expiration Date: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.biz'
        self.update_reg_expressions(self._biz_expressions)


class RegexMOBI(BaseParser): # same as ME

    _mobi_expressions = {}

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.mobi'
        self.update_reg_expressions(RegexME._me_expressions)


class RegexKG(BaseParser):

    _kg_expressions = {
        'registrar': r'Domain support: \s*(.+)',
        'registrant_name': r'Name: *(.+)',
        'registrant_address': r'Address: *(.+)',
        'created': r'Record created: *(.+)',
        'expires': r'Record expires on \s*(.+)',
        'updated': r'Record last updated on\s*(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.kg'
        self.update_reg_expressions(self._kg_expressions)


class RegexCH(BaseParser):

    _ch_expressions = {
        'registrant_name': r'Holder of domain name:\s*(?:.*\n){1}\s*(.+)',
        'registrant_address': r'Holder of domain name:\s*(?:.*\n){2}\s*(.+)',
        'registrar': r'Registrar:\n*(.+)',
        'created': r'First registration date:\n*(.+)',
        'dnssec': r'DNSSEC:*([\S]+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.ch'
        self.update_reg_expressions(self._ch_expressions)


class RegexLI(BaseParser):  # same as CH

    _li_expressions = RegexCH._ch_expressions

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.li'
        self.update_reg_expressions(self._li_expressions)


class RegexID(BaseParser):

    _id_expressions = {
        'created': r'Created On:(.+)',
        'expires': r'Expiration Date:(.+)',
        'updated': r'Last Updated On:(.+)',
        'dnssec': r'DNSSEC:(.+)',
        'registrar': r'Sponsoring Registrar Organization:(.+)',
        'status': r'Status:(.+)',
        'registrant_name': r'Registrant Name:(.+)',
        'registrant_address': r'Registrant Street1:(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.id'
        self.update_reg_expressions(self._id_expressions)


class RegexSE(BaseParser):

    _se_expressions = {
        'registrant_name': r'holder\.*: *(.+)',
        'created': r'created\.*: *(.+)',
        'updated': r'modified\.*: *(.+)',
        'expires': r'expires\.*: *(.+)',
        'dnssec': r'dnssec\.*: *(.+)',
        'status': r'status\.*: *(.+)',
        'registrar': r'registrar: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.iis.se'
        self.update_reg_expressions(self._se_expressions)


class RegexJobs(BaseParser):

    _jobs_expressions = {
        'expires': r'Registrar Registration Expiration Date: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.jobs'
        self.update_reg_expressions(self._jobs_expressions)


class RegexIT(BaseParser):

    _it_expressions = {
        'domain_name': r'Domain: *(.+)',
        'created': r'(?<! )Created: *(.+)',
        'updated': r'(?<! )Last Update: *(.+)',
        'expires': r'(?<! )Expire Date: *(.+)',
        'status': r'Status: *(.+)',
        'registrant_name': r'(?<=Registrant)[\s\S]*?Organization:(.*)',
        'registrant_address': r'(?<=Registrant)[\s\S]*?Address:(.*)',
        'registrar': r'(?<=Registrar)[\s\S]*?Name:(.*)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.it'
        self.update_reg_expressions(self._it_expressions)


class RegexSA(BaseParser):

    _sa_expressions = {
        'created': r'Created on: *(.+)',
        'updated': r'Last Updated on: *(.+)',
        'registrant_name': r'Registrant:\s*(.+)',
        'registrant_address': r'(?<=Registrant)[\s\S]*?Address:((?:.+\n)*)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.net.sa'
        self.update_reg_expressions(self._sa_expressions)


class RegexSK(BaseParser):

    _sk_expressions = {
        'created': r'(?<=Domain:)[\s\w\W]*?Created: *(.+)',
        'updated': r'(?<=Domain:)[\s\w\W]*?Updated: *(.+)',
        'expires': r'Valid Until: *(.+)',
        'registrant_name': r'Name:\s*(.+)',
        'registrant_address': r'Street:\s*(.+)',
        'registrar': r'(?<=Registrar)[\s\S]*?Organization:(.*)',
        'registrant_city': r'(?<=^Contact)[\s\S]*?City:(.*)',
        'registrant_zipcode': r'(?<=^Contact)[\s\S]*?Postal Code:(.*)',
        'registrant_country': r'(?<=^Contact)[\s\S]*?Country Code:(.*)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.sk-nic.sk'
        self.update_reg_expressions(self._sk_expressions)


class RegexMX(BaseParser):

    _mx_expressions = {
        'created': r'Created On: *(.+)',
        'updated': r'Last Updated On: *(.+)',
        'expires': r'Expiration Date: *(.+)',
        'registrar': 'Registrar:\s*(.+)',
        'registrant_name': r'(?<=Registrant)[\s\S]*?Name:(.*)',
        'registrant_city': r'(?<=Registrant)[\s\S]*?City:(.*)',
        'registrant_state': r'(?<=Registrant)[\s\S]*?State:(.*)',
        'registrant_country': r'(?<=Registrant)[\s\S]*?Country:(.*)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.mx'
        self.update_reg_expressions(self._mx_expressions)


class RegexTW(BaseParser):

    _tw_expressions = {
        'created': r'Record created on (.+) ',
        'expires': r'Record expires on (.+) ',
        'registrar': r'Registration Service Provider: *(.+)',
        'registrant_name': r'(?<=Registrant:)\s+(.*)',
        'registrant_city': r'(?<=Registrant:)\s*(?:.*\n){5}\s+(.*),',
        'registrant_address': r'(?<=Registrant:)\s*(?:.*\n){4}\s+(.*)',
        'registrant_state': r'(?<=Registrant:)\s*(?:.*\n){5}.*, (.*)',
        'registrant_country': r'(?<=Registrant:)\s*(?:.*\n){6}\s+(.*)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.twnic.net.tw'
        self.update_reg_expressions(self._tw_expressions)


class RegexTR(BaseParser):

    _tr_expressions = {
        'created': r'Created on.*: *(.+)',
        'expires': r'Expires on.*: *(.+)',
        'registrant_name': r'(?<=[**] Registrant:)[\s\S]((?:\s.+)*)',
        'registrant_address': r'(?<=[**] Administrative Contact)[\s\S]*?Address\s+: (.*)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.tr'
        self.update_reg_expressions(self._tr_expressions)


class RegexIS(BaseParser):

    _is_expressions = {
        'registrant_name': r'registrant: *(.+)',
        'registrant_address': r'address\.*: *(.+)',
        'created': r'created\.*: *(.+)',
        'expires': r'expires\.*: *(.+)',
        'dnssec': r'dnssec\.*: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.isnic.is'
        self.update_reg_expressions(self._is_expressions)


class RegexDK(BaseParser):

    _dk_expressions = {
        'created': r'Registered: *(.+)',
        'expires': r'Expires: *(.+)',
        'dnssec': r'Dnssec: *(.+)',
        'status': r'Status: *(.+)',
        'registrant_name': r'Registrant\s*(?:.*\n){2}\s*Name: *(.+)',
        'registrant_address': r'Registrant\s*(?:.*\n){3}\s*Address: *(.+)',
        'registrant_zipcode': r'Registrant\s*(?:.*\n){4}\s*Postalcode: *(.+)',
        'registrant_city': r'Registrant\s*(?:.*\n){5}\s*City: *(.+)',
        'registrant_country': r'Registrant\s*(?:.*\n){6}\s*Country: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.dk-hostmaster.dk'
        self.update_reg_expressions(self._dk_expressions)


class RegexAI(BaseParser):

    _ai_expressions = {}

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.ai'
        self.update_reg_expressions(self._ai_expressions)


class RegexIL(BaseParser):

    _li_expressions = {
        'expires': r'validity: *(.+)',
        'registrant_name': r'person: *(.+)',
        'registrant_address': r'address *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'status': r'status: *(.+)',
        'registrar': r'registrar name: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.isoc.org.il'
        self.update_reg_expressions(self._li_expressions)


class RegexIN(BaseParser):

    _in_expression = {
        'registrar': r'Registrar: *(.+)',
        'updated': r'Updated Date: (\d{4}-\d{2}-\d{2})',
        'created': r'Creation Date: (\d{4}-\d{2}-\d{2})',
        'expires': r'Registry Expiry Date: (\d{4}-\d{2}-\d{2})',
        'name_servers': r'Name Server: *(.+)',
        'registrant_organization': r'Registrant Organization: *(.+)',
        'registrant_state': r'Registrant State/Province: *(.+)',
        'status': r'Status: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
        'dnssec': r'DNSSEC: *([\S]+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.registry.in'
        self.update_reg_expressions(self._in_expression)


class RegexCAT(BaseParser):

    _cat_expressions = {
        'expires': r'Registrar Registration Expiration Date: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.cat'
        self.update_reg_expressions(self._cat_expressions)


class RegexIE(BaseParser):

    _ie_expressions = {
        'registrant_name': r'Domain Holder: *(.+)',
        'created': r'Registration Date: *(.+)',
        'expires': r'Renewal Date: *(.+)',
        'name_servers': r'Nserver: *(.+)',
        'status': r'Renewal status: *(.+)',
        'registrar': r'Account Name: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.iedr.ie'
        self.update_reg_expressions(self._ie_expressions)


class RegexNZ(BaseParser):

    _nz_expressions = {
        'registrar': r'registrar_name:\s*([^\n\r]+)',
        'updated': r'domain_datelastmodified:\s*([^\n\r]+)',
        'created': r'domain_dateregistered:\s*([^\n\r]+)',
        'expires': r'domain_datebilleduntil:\s*([^\n\r]+)',
        'name_servers': r'ns_name_\d*:\s*([^\n\r]+)',
        'status': r'status:\s*([^\n\r]+)',
        'registrant_name': r'registrant_contact_name:\s*([^\n\r]+)',
        'registrant_address': r'registrant_contact_address\d*:\s*([^\n\r]+)',
        'registrant_city': r'registrant_contact_city:\s*([^\n\r]+)',
        'registrant_zipcode': r'registrant_contact_postalcode:\s*([^\n\r]+)',
        'registrant_country': r'registrant_contact_country:\s*([^\n\r]+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.srs.net.nz'
        self.update_reg_expressions(self._nz_expressions)


class RegexLU(BaseParser):

    _lu_expressions = {
        'created': r'registered: *(.+)',
        'name_servers': r'nserver: *(.+)',
        'status': r'domaintype: *(.+)',
        'registrar': r'registrar-name: *(.+)',
        'registrant_organization': r'org-name: *(.+)',
        'registrant_address': r'org-address: *(.+)',
        'registrant_zipcode': r'org-zipcode:*(.+)',
        'registrant_city': r'org-city: *(.+)',
        'registrant_country': r'org-country: *(.+)',
        # 'admin_name':               'adm-name: *(.+)',
        # 'admin_address':            'adm-address: *(.+)',
        # 'admin_postal_code':        'adm-zipcode: *(.+)',
        # 'admin_city':               'adm-city: *(.+)',
        # 'admin_country':            'adm-country: *(.+)',
        # 'admin_email':              'adm-email: *(.+)',
        # 'tech_name':                'tec-name: *(.+)',
        # 'tech_address':             'tec-address: *(.+)',
        # 'tech_postal_code':         'tec-zipcode: *(.+)',
        # 'tech_city':                'tec-city: *(.+)',
        # 'tech_country':             'tec-country: *(.+)',
        # 'tech_email':               'tec-email: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.dns.lu'
        self.update_reg_expressions(self._lu_expressions)


class RegexCZ(BaseParser):

    _cz_expressions = {
        'registrant_name': r'registrant: *(.+)',
        'registrar': r'registrar: *(.+)',
        'created': r'registered: *(.+)',
        'updated': r'changed: *(.+)',
        'expires': r'expire: *(.+)',
        'name_servers': r'nserver: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.cz'
        self.update_reg_expressions(self._cz_expressions)


class RegexONLINE(BaseParser):

    _online_expressions = {
        'name_servers': r'Name Server: *(.+)',
        'expires': r'Registrar Registration Expiration Date: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.online'
        self.update_reg_expressions(self._online_expressions)


class RegexHR(BaseParser):

    _hr_expressions = {
        'domain_name': 'Domain Name: *(.+)',
        'updated': 'Updated Date: *(.+)',
        'created': 'Creation Date: *(.+)',
        'expires': 'Registrar Registration Expiration Date: *(.+)',
        'name_servers': 'Name Server: *(.+)',
        'registrant_name': 'Registrant Name:\s(.+)',
        'registrant_address': 'Registrant Street:\s*(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.dns.hr'
        self.update_reg_expressions(self._hr_expressions)


class RegexHK(BaseParser):

    _hk_expressions = {
        'status': r'Domain Status: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'registrar': r'Registrar Name: *(.+)',
        'registrant_name': r'Registrant Contact Information:\s*Company English Name.*:(.+)',
        'registrant_address': r'(?<=Registrant Contact Information:)[\s\S]*?Address: (.*)',
        'registrant_country': r'[Registrant Contact Information\w\W]+Country: ([\S\ ]+)',
        'registrant_email': r'[Registrant Contact Information\w\W]+Email: ([\S\ ]+)',
        'updated': r'Updated Date: *(.+)',
        'created': r'[Registrant Contact Information\w\W]+Domain Name Commencement Date: (.+)',
        'expires': r'[Registrant Contact Information\w\W]+Expiry Date: (.+)',
        'name_servers': r'Name Servers Information:\s+((?:.+\n)*)'

        # 'admin_name':                     '[Administrative Contact Information\w\W]+Given name: ([\S\ ]+)',
        # 'admin_family_name':              '[Administrative Contact Information\w\W]+Family name: ([\S\ ]+)',
        # 'admin_company_name':             '[Administrative Contact Information\w\W]+Company name: ([\S\ ]+)',
        # 'admin_address':                  '(?<=Administrative Contact Information:)[\s\S]*?Address: (.*)',
        # 'admin_country':                  '[Administrative Contact Information\w\W]+Country: ([\S\ ]+)',
        # 'admin_phone':                    '[Administrative Contact Information\w\W]+Phone: ([\S\ ]+)',
        # 'admin_fax':                      '[Administrative Contact Information\w\W]+Fax: ([\S\ ]+)',
        # 'admin_email':                    '[Administrative Contact Information\w\W]+Email: ([\S\ ]+)',
        # 'admin_account_name':             '[Administrative Contact Information\w\W]+Account Name: ([\S\ ]+)',
        #
        # 'tech_name':                      '[Technical Contact Information\w\W]+Given name: (.+)',
        # 'tech_family_name':               '[Technical Contact Information\w\W]+Family name: (.+)',
        # 'tech_company_name':              '[Technical Contact Information\w\W]+Company name: (.+)',
        # 'tech_address':                   '(?<=Technical Contact Information:)[\s\S]*?Address: (.*)',
        # 'tech_country':                   '[Technical Contact Information\w\W]+Country: (.+)',
        # 'tech_phone':                     '[Technical Contact Information\w\W]+Phone: (.+)',
        # 'tech_fax':                       '[Technical Contact Information\w\W]+Fax: (.+)',
        # 'tech_email':                     '[Technical Contact Information\w\W]+Email: (.+)',
        # 'tech_account_name':              '[Technical Contact Information\w\W]+Account Name: (.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.hkirc.hk'
        self.update_reg_expressions(self._hk_expressions)


class RegexUA(BaseParser):

    _ua_expressions = {
        'domain_name': r'domain: *(.+)',
        'status': r'status: *(.+)',
        'registrar': r'(?<=Registrar:)[\s\W\w]*?organization-loc:(.*)',
        'registrant_name': r'(?<=Registrant:)[\s\W\w]*?organization-loc:(.*)',
        'registrant_country': r'(?<=Registrant:)[\s\W\w]*?country-loc:(.*)',
        'registrant_city': r'(?<=Registrant:)[\s\W\w]*?(?:address\-loc:\s+.*\n){2}address-loc:\s+(.*)\n',
        'registrant_state': r'(?<=Registrant:)[\s\W\w]*?(?:address\-loc:\s+.*\n){1}address-loc:\s+(.*)\n',
        'registrant_address': r'(?<=Registrant:)[\s\W\w]*?address-loc:\s+(.*)\n',
        'registrant_zipcode': r'(?<=Registrant:)[\s\W\w]*?postal-code-loc:(.*)',
        'updated': 'modified: *(.+)',
        'created': 'created: (.+)',
        'expires': 'expires: (.+)',
        'name_servers': 'nserver: *(.+)'
        # 'admin':                         '(?<=Administrative Contacts:)[\s\W\w]*?organization-loc:(.*)',
        # 'admin_country':                 '(?<=Administrative Contacts:)[\s\W\w]*?country-loc:(.*)',
        # 'admin_city':                    '(?<=Administrative Contacts:)[\s\W\w]*?(?:address\-loc:\s+.*\n){2}address-loc:\s+(.*)\n',
        # 'admin_state':                   '(?<=Administrative Contacts:)[\s\W\w]*?(?:address\-loc:\s+.*\n){1}address-loc:\s+(.*)\n',
        # 'admin_address':                 '(?<=Administrative Contacts:)[\s\W\w]*?address-loc:\s+(.*)\n',
        # 'admin_email':                   '(?<=Administrative Contacts:)[\s\W\w]*?e-mail:(.*)',
        # 'admin_postal_code':             '(?<=Administrative Contacts:)[\s\W\w]*?postal-code-loc:(.*)',
        # 'admin_phone':                   '(?<=Administrative Contacts:)[\s\W\w]*?phone:(.*)',
        # 'admin_fax':                     '(?<=Administrative Contacts:)[\s\W\w]*?fax:(.*)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.ua'
        self.update_reg_expressions(self._ua_expressions)


class RegexHN(BaseParser):

    _hn_expressions = {
        'status':                   r'Domain Status: *(.+)',
        'registrar':                r'Registrar: *(.+)',
        'registrant_name':          r'Registrant Name: (.+)',
        'registrant_organization':  r'Registrant Organization: (.+)',
        'registrant_city':          r'Registrant City: (.*)',
        'registrant_address':       r'Registrant Street: (.*)',
        'registrant_state':         r'Registrant State/Province: (.*)',
        'registrant_zipcode':       r'Registrant Postal Code: (.*)',
        'registrant_country':       r'Registrant Country: (.+)',
        'registrant_phone':         r'Registrant Phone: (.+)',
        'registrant_fax':           r'Registrant Fax: (.+)',
        'registrant_email':         r'Registrant Email: (.+)',
        'updated':                  r'Updated Date: *(.+)',
        'created':                  r'Creation Date: *(.+)',
        'expires':                  r'Registry Expiry Date: *(.+)',
        'name_servers':             r'Name Server: *(.+)'
        # 'admin_name':                     'Admin Name: (.+)',
        # 'admin_id':                       'Admin ID: (.+)',
        # 'admin_organization':             'Admin Organization: (.+)',
        # 'admin_city':                     'Admin City: (.*)',
        # 'admin_street':                   'Admin Street: (.*)',
        # 'admin_state_province':           'Admin State/Province: (.*)',
        # 'admin_postal_code':              'Admin Postal Code: (.*)',
        # 'admin_country':                  'Admin Country: (.+)',
        # 'admin_phone':                    'Admin Phone: (.+)',
        # 'admin_fax':                      'Admin Fax: (.+)',
        # 'admin_email':                    'Admin Email: (.+)',
        #
        # 'billing_name':                   'Billing Name: (.+)',
        # 'billing_id':                     'Billing ID: (.+)',
        # 'billing_organization':           'Billing Organization: (.+)',
        # 'billing_city':                   'Billing City: (.*)',
        # 'billing_street':                 'Billing Street: (.*)',
        # 'billing_state_province':         'Billing State/Province: (.*)',
        # 'billing_postal_code':            'Billing Postal Code: (.*)',
        # 'billing_country':                'Billing Country: (.+)',
        # 'billing_phone':                  'Billing Phone: (.+)',
        # 'billing_fax':                    'Billing Fax: (.+)',
        # 'billing_email':                  'Billing Email: (.+)',
        #
        # 'tech_name':                      'Tech Name: (.+)',
        # 'tech_id':                        'Tech ID: (.+)',
        # 'tech_organization':              'Tech Organization: (.+)',
        # 'tech_city':                      'Tech City: (.*)',
        # 'tech_street':                    'Tech Street: (.*)',
        # 'tech_state_province':            'Tech State/Province: (.*)',
        # 'tech_postal_code':               'Tech Postal Code: (.*)',
        # 'tech_country':                   'Tech Country: (.+)',
        # 'tech_phone':                     'Tech Phone: (.+)',
        # 'tech_fax':                       'Tech Fax: (.+)',
        # 'tech_email':                     'Tech Email: (.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.hn'
        self.update_reg_expressions(self._hn_expressions)


class RegexLAT(BaseParser):

    _lat_expressions = {
        'status': r'Domain Status: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'registrant_name': r'Registrant Name: (.+)',
        'registrant_organization': r'Registrant Organization: (.+)',
        'registrant_city': r'Registrant City: (.*)',
        'registrant_address': r'Registrant Street: (.*)',
        'registrant_state': r'Registrant State/Province: (.*)',
        'registrant_zipcode': r'Registrant Postal Code: (.*)',
        'registrant_country': r'Registrant Country: (.+)',
        'updated': r'Updated Date: *(.+)',
        'created': r'Creation Date: *(.+)',
        'expires': r'Registry Expiry Date: *(.+)',
        'name_servers': r'Name Server: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.lat'
        self.update_reg_expressions(self._lat_expressions)


class RegexCN(BaseParser):

    _cn_expressions = {
        'registrar': r'Registrar: *(.+)',
        'created': r'Registration Time: *(.+)',
        'expires': r'Expiration Time: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'status': r'Status: *(.+)',
        'dnssec': r'dnssec: *([\S]+)',
        'registrant_name': r'Registrant: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.cnnic.cn'
        self.update_reg_expressions(self._cn_expressions)


class RegexAPP(BaseParser):

    _app_expressions = {
        'registrar': r'Registrar: *(.+)',
        'updated': r'Updated Date: *(.+)',
        'created': r'Creation Date: *(.+)',
        'expires': r'Expir\w+ Date: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'status': r'Status: *(.+)',
        'dnssec': r'dnssec: *([\S]+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_organization': r'Registrant\s*Organization: *(.+)',
        'registrant_address': r'Registrant Street: *(.+)',
        'registrant_city': r'Registrant City: *(.+)',
        'registrant_state': r'Registrant State/Province: *(.+)',
        'registrant_zipcode': r'Registrant Postal Code: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.google'
        self.update_reg_expressions(self._app_expressions)


class RegexMONEY(BaseParser):

    _money_expressions = {
        'domain_name': r'Domain Name: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'updated': r'Updated Date: *(.+)',
        'created': r'Creation Date: *(.+)',
        'expires': r'Registry Expiry Date: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'status': r'Domain Status: *(.+)',
        'dnssec': r'DNSSEC: *(.+)',
        'registrant_name': r'Registrant Name: *(.+)',
        'registrant_organization': r'Registrant Organization: *(.+)',
        'registrant_address': r'Registrant Street: *(.+)',
        'registrant_city': r'Registrant City: *(.+)',
        'registrant_state': r'Registrant State/Province: *(.+)',
        'registrant_zipcode': r'Registrant Postal Code: *(.+)',
        'registrant_country': r'Registrant Country: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.money'
        self.update_reg_expressions(self._money_expressions)


class RegexAR(BaseParser):

    _ar_expressions = {
        'domain_name': r'domain: *(.+)',
        'registrar': r'registrar: *(.+)',
        'updated': r'changed: *(.+)',
        'created': r'created: *(.+)',
        'expires': r'expire: *(.+)',
        'name_servers': r'nserver: *(.+) \(.*\)',
        'status': r'Domain Status: *(.+)',
        'registrant_name': r'name: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.ar'
        self.update_reg_expressions(self._ar_expressions)


class RegexBY(BaseParser):

    _by_expressions = {
        'domain_name': r'Domain Name: *(.+)',
        'registrar': r'Registrar: *(.+)',
        'updated': r'Updated Date: *(.+)',
        'created': r'Creation Date: *(.+)',
        'expires': r'Expiration Date: *(.+)',
        'name_servers': r'Name Server: *(.+)',
        'status': r'Domain Status: *(.+)',
        'registrant_name': r'Person: *(.+)',
        'registrant_organization': r'Org: *(.+)',
        'registrant_country': r'Country: *(.+)',
        'registrant_address': r'Address: *(.+)',
        'registrant_phone': r'Phone: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.cctld.by'
        self.update_reg_expressions(self._by_expressions)


class RegexCR(BaseParser):

    _cr_expressions = {
        'domain_name': r'domain: *(.+)',
        'registrant_name': r'registrant: *(.+)',
        'registrar': r'registrar: *(.+)',
        'updated': r'changed: *(.+)',
        'created': r'registered: *(.+)',
        'expires': r'expire: *(.+)',
        'name_servers': r'nserver: *(.+)',
        'status': r'status: *(.+)',
        'registrant_organization': r'org: *(.+)',
        'registrant_address': r'address: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.cr'
        self.update_reg_expressions(self._cr_expressions)


class RegexVE(BaseParser):

    _ve_expressions = {
        'domain_name': r'Nombre de Dominio: *(.+)',
        'status': r'Estatus del dominio: *(.+)',
        'registrar': r'registrar: *(.+)',
        'updated': r'Ultima Actualización: *(.+)',
        'created': r'Fecha de Creación: *(.+)',
        'expires': r'Fecha de Vencimiento: *(.+)',
        'name_servers': r'Nombres de Dominio:((?:\s+- .*)*)',
        'registrant_name': r'Titular:\s*(?:.*\n){1}\s+(.*)',
        'registrant_city': r'Titular:\s*(?:.*\n){3}\s+([\s\w]*)',
        'registrant_address': r'Titular:\s*(?:.*\n){2}\s+(.*)',
        'registrant_state': r'Titular:\s*(?:.*\n){3}\s+.*?,(.*),',
        'registrant_country': r'Titular:\s*(?:.*\n){3}\s+.*, .+  (.*)',
        'registrant_phone': r'Titular:\s*(?:.*\n){4}\s+(\+*\d.+)',
        'registrant_email': r'Titular:\s*.*\t(.*)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.ve'
        self.update_reg_expressions(self._ve_expressions)


class RegexDO(BaseParser):

    _do_expressions = {}

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.do'
        self.update_reg_expressions(self._do_expressions)


class RegexAE(BaseParser):

    _ae_expressions = {
        'status': r'Status: *(.+)',
        'registrant_name': r'Registrant Contact Name: *(.+)',
        'tech_name': r'Tech Contact Name: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.aeda.net.ae'
        self.update_reg_expressions(self._ae_expressions)


class RegexSI(BaseParser):

    _si_expressions = {
        'registrar': r'registrar: *(.+)',
        'name_servers': r'nameserver: *(.+)',
        'registrant_name': r'registrant: *(.+)',
        'created': r'created: *(.+)',
        'expires': r'expire: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.register.si'
        self.update_reg_expressions(self._si_expressions)


class RegexNO(BaseParser):

    _no_expressions = {
        'created': r'Additional information:\nCreated:\s*(.+)',
        'updated': r'Additional information:\n(?:.*\n)Last updated:\s*(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.norid.no'
        self.update_reg_expressions(self._no_expressions)


class RegexKZ(BaseParser):

    _kz_expressions = {
        'registar_created': r'Registar Created: *(.+)',  # TYPOS are on the whois server
        'registrar': r'Current Registar: *(.+)',  # TYPOS are on the whois server
        'created': r'Domain created: *(.+)',
        'updated': r'Last modified : *(.+)',
        'name_servers': r'server.*: *(.+)',
        'status': r' (.+?) -',
        'registrant_organization': r'Organization Name.*: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.kz'
        self.update_reg_expressions(self._kz_expressions)


class RegexTOP(BaseParser):

    _top_expressions = {
        'expires': r'Registrar Registration Expiration Date: (\d{4}-\d{2}-\d{2})'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.top'
        self.update_reg_expressions(self._top_expressions)


class RegexIR(BaseParser):

    _ir_expressions = {
        'updated': r'last-updated: *(.+)',
        'expires': r'expire-date: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.ir'
        self.update_reg_expressions(self._ir_expressions)


class RegexXYZ(BaseParser):

    _xyz_expressions = {
        'expires': r'Registrar Registration Expiration Date: (\d{4}-\d{2}-\d{2})'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.xyz'
        self.update_reg_expressions(self._xyz_expressions)


class RegexICU(BaseParser):

    _icu_expressions = {
        'created': r'Creation Date: (\d{4}-\d{2}-\d{2})',
        'updated': r'Updated Date: (\d{4}-\d{2}-\d{2})',
        'expires': r'Registrar Registration Expiration Date: (\d{4}-\d{2}-\d{2})'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.icu'
        self.update_reg_expressions(self._icu_expressions)


class RegexTK(BaseParser):

    _tk_expressions = {
        'created': r'Domain registered: *(.+)',
        'expires': r'Record will expire on: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.dot.tk'
        self.update_reg_expressions(self._tk_expressions)
