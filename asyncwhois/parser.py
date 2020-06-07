from typing import Dict, Any, Union
import datetime
import re

from .errors import WhoIsQueryError


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

    def parse(self, blob: str) -> Dict[str, Any]:
        parsed = {}
        keys_can_be_lists = ['status', 'name_servers']
        for key, regex in self.reg_expressions.items():
            if not regex:
                parsed[key] = None
            else:
                many = key in keys_can_be_lists
                parsed[key] = self.find_match(regex, blob, many)
        return parsed

    def update_reg_expressions(self, expressions_update: Dict[str, Any]) -> None:
        expressions = self.base_expressions.copy()
        expressions.update(expressions_update)
        self.reg_expressions = expressions

    def find_match(self, regex: str, blob: str, many: bool = False) -> Union[str, None]:
        match = re.search(regex, blob, flags=re.IGNORECASE)
        if match:
            return match.group(1).rstrip('\r').lstrip('\t')
        else:
            return None


class WhoIsParser:

    def __init__(self, top_level_domain: str):
        self.parser_output = {}
        self._parser = self._init_parser(top_level_domain)

    def parse(self, blob: str) -> None:
        no_match_checks = ['no match', 'not found']
        if any([n in blob.lower() for n in no_match_checks]):
            raise WhoIsQueryError(f'Domain not found: {blob}')
        self.parser_output = self._parser.parse(blob)
        # self._parse_dates()

    # def _parse_dates(self):
    #     for date_key in ['created', 'updated', 'expires']:
    #         date_string = self.parser_output.get(date_key)
    #         if date_string:
    #             date_converted = datetime.date()

    def _init_parser(self, tld: str) -> BaseParser:
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
        # elif tld == 'eu':
        #     return RegexEU()
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
        elif tld == 'registrant_organization':
            return RegexORG()
        elif tld == 'pe':
            return RegexPE()
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

    _com_expressions = {}

    def __init__(self):
        super().__init__()
        self.server = 'whois.verisign-grs.com'
        self.update_reg_expressions(self._com_expressions)


class RegexNET(BaseParser):

    _net_expressions = {
        'expires': 'Registrar Registration Expiration Date: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.verisign-grs.com'
        self.update_reg_expressions(self._net_expressions)


class RegexORG(BaseParser):

    _org_expressions = {
        'expires': 'Registry Expiry Date: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.pir.org'
        self.update_reg_expressions(self._org_expressions)


class RegexRU(BaseParser):

    _ru_expressions = {
        'created': 'created: *(.+)',
        'expires': 'paid-till: *(.+)',
        'organization': 'org: *(.+)',
        'status': 'state: *(.+)',
        'name_servers': 'nserver: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.tcinet.ru'
        self.update_reg_expressions(self._ru_expressions)


class RegexCL(BaseParser):

    _cl_expressions = {
        'name_servers': 'Name server: *(.+)',
        'registrant_name': 'Registrant name: *(.+)',
        'registrant_organization': 'Registrant organisation: *(.+)',
        'registrar': 'registrar name: *(.+)',
        'expires': 'Expiration date: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.cl'
        self.update_reg_expressions(self._cl_expressions)


class RegexCO(BaseParser):

    _co_expressions = {}

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.co'
        self.update_reg_expressions(self._co_expressions)


class RegexPL(BaseParser):

    _pl_expressions = {
        'domain_name': 'DOMAIN NAME: *(.+)\n',
        'name_servers': 'nameservers:((?:\s+.+\n+)*)',
        'registrar': 'REGISTRAR:\s*(.+)',
        'created': '(?<! )created: *(.+)\n',
        'expires': 'renewal date: *(.+)',
        'updated': 'last modified: *(.+)\n',
        'dnssec': 'dnssec: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.dns.pl'
        self.update_reg_expressions(self._pl_expressions)


class RegexRO(BaseParser):
    # % The ROTLD WHOIS service on port 43 never discloses any information concerning the registrant.

    _ro_expressions = {
        'created': 'Registered On: *(.+)',
        'expires': 'Expires On: *(.+)',
        'name_servers': 'Nameserver: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.rotld.ro'
        self.update_reg_expressions(self._ro_expressions)


class RegexPE(BaseParser):

    _pe_expressions = {
        'registrant_name': 'Registrant name: *(.+)',
        'registrar': 'Sponsoring Registrar: *(.+)',
        'admin': 'Admin Name: *(.+)',
        'dnssec': 'DNSSEC: *(.+)',
        'name_servers': 'Name server: *(.+)',
        'status': 'Domain Status: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'kero.yachay.pe'
        self.update_reg_expressions(self._pe_expressions)


class RegexSPACE(BaseParser):

    _space_expressions = {
        'expires': 'Registrar Registration Expiration Date: *(.+)'
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


class RegexCA(BaseParser):

    _ca_expressions = {}

    def __init__(self):
        super().__init__()
        self.server = 'whois.cira.ca'
        self.update_reg_expressions(self._ca_expressions)


class RegexFR(BaseParser):

    _fr_expressions = {
        'created': 'created: (\d{4}-\d{2}-\d{2})',
        'updated': 'last-update: (\d{4}-\d{2}-\d{2})',
        'expires': 'Expiry Date: (\d{4}-\d{2}-\d{2})',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.fr'
        self.update_reg_expressions(self._fr_expressions)


class RegexBR(BaseParser):

    _br_expressions = {
        'created': 'created: ',
        'updated': 'changed: ',
        'status': 'status: *(.+)',
        'registrant_name': 'responsible: *(.+)',
        'registrant_country': 'country: *(.+)',
        'expires':  'expires: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.registro.br'
        self.update_reg_expressions(self._br_expressions)


class RegexKR(BaseParser):

    _kr_expressions = {
        'created': 'Registered Date *: (\d{4}\.\s\d{2}\.\s\d{2}\.)',
        'updated': 'Last Updated Date *: (\d{4}\.\s\d{2}\.\s\d{2}\.)',
        'expires': 'Expiration Date *: (\d{4}\.\s\d{2}\.\s\d{2}\.)',
        'registrant_name': 'Registrant *: (.+)',
        'dnssec': 'DNSSEC *: (.+)',
        'registrant_zipcode': 'Registrant Zip Code: *: (.+)',
        'registrant_address': 'Registrant Address *: (.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.kr'
        self.update_reg_expressions(self._kr_expressions)


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
        'updated': 'Changed: (\d{4}\.\s\d{2}\.\s\d{2}\.)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.denic.de'
        self.update_reg_expressions(self._de_expressions)


class RegexUK(BaseParser):

    _uk_expressions = {
        'created': 'Registered on: (\d{2}-\w{3}-\d{4})',
        'updated': 'Last updated: (\d{2}-\w{3}-\d{4})',
        'expires': 'Expiry date: (\d{2}-\w{3}-\d{4})',
        'registrar': 'Registrar:\s *(.+)'
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
        'registrar': 'registrar: *(.+)',
        'registrant_name': 'personname: *(.+)',
        'registrant_address': 'street address: *(.+)',
        'registrant_zipcode': 'postal code: *(.+)',
        'registrant_city': 'city: *(.+)',
        'registrant_country': 'country: *(.+)',
        'updated': 'changed: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.at'
        self.update_reg_expressions(self._at_expressions)


class RegexBE(BaseParser):

    _be_expressions = {
        'registrant_name': 'Name: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.dns.be'
        self.update_reg_expressions(self._be_expressions)


class RegexINFO(BaseParser):

    _info_expressions = {
        'registrar':                   'Registrar: *(.+)',
        'updated':                     'Updated Date: *(.+)',
        'created':                     'Creation Date: *(.+)',
        'expires':                     'Registry Expiry Date: *(.+)',
        'status':                      'Status: *(.+)',
        'registrant_name':             'Registrant Name: *(.+)',
        'registrant_organization':     'Registrant Organization: *(.+)',
        'registrant_address':          'Registrant Street: *(.+)',
        'registrant_city':             'Registrant City: *(.+)',
        'registrant_state':            'Registrant State/Province: *(.+)',
        'registrant_zipcode':          'Registrant Postal Code: *(.+)',
        'registrant_country':          'Registrant Country: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.afilias.net'
        self.update_reg_expressions(self._info_expressions)


class RegexRF(BaseParser): # same as RU

    def __init__(self):
        super().__init__()
        self.server = 'whois.tcinet.ru'
        self.update_reg_expressions(RegexRU._ru_expressions)


class RegexSU(BaseParser):

    _su_expressions = {}

    def __init__(self):
        super().__init__()
        self.server = 'whois.tcinet.ru'
        self.update_reg_expressions(self._su_expressions)


class RegexClub(BaseParser):

    _club_expressions = {
        'registrar': 'Sponsoring Registrar: *(.+)',
        'status': 'Domain Status: *(.+)',
        'registrant_name': 'Registrant Name: *(.+)',
        'registrant_city':    'Registrant City: *(.+)',
        'registrant_state':   'Registrant State/Province: *(.+)',
        'registrant_zipcode': 'Registrant Postal Code: *(.+)',
        'registrant_country': 'Registrant Country: *(.+)',
        'created': 'Domain Registration Date: *(.+)',
        'expires': 'Domain Expiration Date: *(.+)',
        'updated': 'Domain Last Updated Date: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.club'
        self.update_reg_expressions(self._club_expressions)


class RegexIO(BaseParser):

    _io_expressions = {
        'registrar':    'Registrar: *(.+)',
        'status':       'Domain Status: *(.+)',
        'registrant_name':   'Registrant Organization: *(.+)',
        'registrant_state':        'Registrant State/Province: *(.+)',
        'registrant_country':      'Registrant Country: *(.+)',
        'created':      'Creation Date: *(.+)',
        'expires':      'Registry Expiry Date: *(.+)',
        'updated':      'Updated Date: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.io'
        self.update_reg_expressions(self._io_expressions)


class RegexBIZ(BaseParser):

    _biz_expressions = {
        'registrar':                      'Registrar: *(.+)',
        'status':                       'Domain Status: *(.+)',  
        'registrant_name':                'Registrant Name: *(.+)',
        'registrant_address':             'Registrant Street: *(.+)',
        'registrant_city':                'Registrant City: *(.+)',
        'registrant_state':      'Registrant State/Province: *(.+)',
        'registrant_zipcode':         'Registrant Postal Code: *(.+)',
        'registrant_country':             'Registrant Country: *(.+)',
        'created':                  'Creation Date: *(.+)',
        'expires':                'Registrar Registration Expiration Date: *(.+)',
        'updated':                   'Updated Date: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.biz'
        self.update_reg_expressions(self._biz_expressions)


class RegexMOBI(BaseParser):

    _mobi_expressions = RegexME._me_expressions

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.mobi'
        self.update_reg_expressions(self._mobi_expressions)


class RegexKG(BaseParser):

    _kg_expressions = {
        'registrar': 'Domain support: \s*(.+)',
        'registrant_name': 'Name: *(.+)',
        'registrant_address': 'Address: *(.+)',
        'created': 'Record created: *(.+)',
        'expires': 'Record expires on \s*(.+)',
        'updated': 'Record last updated on\s*(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.kg'
        self.update_reg_expressions(self._kg_expressions)


class RegexCH(BaseParser):

    _ch_expressions = {
        'registrant_name': 'Holder of domain name:\s*(?:.*\n){1}\s*(.+)',
        'registrant_address': 'Holder of domain name:\s*(?:.*\n){2}\s*(.+)',
        'registrar': 'Registrar:\n*(.+)',
        'created': 'First registration date:\n*(.+)',
        'dnssec': 'DNSSEC:*([\S]+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.ch'
        self.update_reg_expressions(self._ch_expressions)


class RegexLI(BaseParser):

    _li_expressions = RegexCH._ch_expressions

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.li'
        self.update_reg_expressions(self._li_expressions)


class RegexID(BaseParser):

    _id_expressions = {
        'created':               'Created On:(.+)',
        'expires':             'Expiration Date:(.+)',
        'updated':                'Last Updated On:(.+)',
        'dnssec':                      'DNSSEC:(.+)',
        'registrar':                   'Sponsoring Registrar Organization:(.+)',
        'status':                      'Status:(.+)',  
        'registrant_name':             'Registrant Name:(.+)',
        'registrant_address':          'Registrant Street1:(.+)',
        'registrant_city':             'Registrant City:(.+)',
        'registrant_country':          'Registrant Country:(.+)',
        'registrant_zipcode':      'Registrant Postal Code:(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.id'
        self.update_reg_expressions(self._id_expressions)


class RegexSE(BaseParser):

    _se_expressions = {
        'registrant_name':                'holder\.*: *(.+)',
        'created':                  'created\.*: *(.+)',
        'updated':                   'modified\.*: *(.+)',
        'expires':                'expires\.*: *(.+)',
        'dnssec':                         'dnssec\.*: *(.+)',
        'status':                         'status\.*: *(.+)',  
        'registrar':                      'registrar: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.iis.se'
        self.update_reg_expressions(self._se_expressions)


class RegexJobs(BaseParser):

    _jobs_expressions = {
        'status':                         'Domain Status: *(.+)',
        'registrar':                 'Registrar: *(.+)',
        'registrant_name':                'Registrant Name: (.+)',
        'registrant_city':                'Registrant City: (.*)',
        'street':              'Registrant Street: (.*)',
        'registrant_state':      'Registrant State/Province: (.*)',
        'registrant_zipcode':         'Registrant Postal Code: (.*)',
        'registrant_country':             'Registrant Country: (.+)',
        'updated':                   'Updated Date: *(.+)',
        'created':                  'Creation Date: *(.+)',
        'expires':                'Registry Expiry Date: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.jobs'
        self.update_reg_expressions(self._jobs_expressions)


class RegexIT(BaseParser):

    _it_expressions = {
        'domain_name':                    'Domain: *(.+)',
        'created':                  '(?<! )Created: *(.+)',
        'updated':                   '(?<! )Last Update: *(.+)',
        'expires':                '(?<! )Expire Date: *(.+)',
        'status':                         'Status: *(.+)',  
        'registrant_name':        '(?<=Registrant)[\s\S]*?Organization:(.*)',
        'registrant_address':             '(?<=Registrant)[\s\S]*?Address:(.*)',
        'registrar':                 '(?<=Registrar)[\s\S]*?Name:(.*)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.it'
        self.update_reg_expressions(self._it_expressions)


class RegexSA(BaseParser):

    _sa_expressions = {
        'created':                  'Created on: *(.+)',
        'updated':                   'Last Updated on: *(.+)',
        'registrant_name':       'Registrant:\s*(.+)',
        'registrant_address':       '(?<=Registrant)[\s\S]*?Address:((?:.+\n)*)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.net.sa'
        self.update_reg_expressions(self._sa_expressions)


class RegexSK(BaseParser):

    _sk_expressions = {
        'created':                  '(?<=Domain:)[\s\w\W]*?Created: *(.+)',
        'updated':                   '(?<=Domain:)[\s\w\W]*?Updated: *(.+)',
        'expires':                'Valid Until: *(.+)',
        'registrant_name':                'Name:\s*(.+)',
        'registrant_address':             'Street:\s*(.+)',
        'registrar':                      '(?<=Registrar)[\s\S]*?Organization:(.*)',
        'registrant_city':                     '(?<=^Contact)[\s\S]*?City:(.*)',
        'registrant_zipcode':              '(?<=^Contact)[\s\S]*?Postal Code:(.*)',
        'registrant_country':             '(?<=^Contact)[\s\S]*?Country Code:(.*)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.sk-nic.sk'
        self.update_reg_expressions(self._sk_expressions)


class RegexMX(BaseParser):

    _mx_expressions = {
        'created':                  'Created On: *(.+)',
        'updated':                   'Last Updated On: *(.+)',
        'expires':                'Expiration Date: *(.+)',
        'registrar':                      'Registrar:\s*(.+)',
        'registrant_name':                '(?<=Registrant)[\s\S]*?Name:(.*)',
        'registrant_city':                '(?<=Registrant)[\s\S]*?City:(.*)',
        'registrant_state':               '(?<=Registrant)[\s\S]*?State:(.*)',
        'registrant_country':             '(?<=Registrant)[\s\S]*?Country:(.*)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.mx'
        self.update_reg_expressions(self._mx_expressions)


class RegexTW(BaseParser):

    _tw_expressions = {
        'created':                  'Record created on (.+) ',
        'expires':                'Record expires on (.+) ',
        'registrar':                      'Registration Service Provider: *(.+)',
        'registrant_name':                '(?<=Registrant:)\s+(.*)',
        'registrant_city':                '(?<=Registrant:)\s*(?:.*\n){5}\s+(.*),',
        'registrant_address':              '(?<=Registrant:)\s*(?:.*\n){4}\s+(.*)',
        'registrant_state':      '(?<=Registrant:)\s*(?:.*\n){5}.*, (.*)',
        'registrant_country':             '(?<=Registrant:)\s*(?:.*\n){6}\s+(.*)',

    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.twnic.net.tw'
        self.update_reg_expressions(self._tw_expressions)


class RegexTR(BaseParser):

    _tr_expressions = {
        'created':                  'Created on.*: *(.+)',
        'expires':                'Expires on.*: *(.+)',
        'registrant_name':                '(?<=[**] Registrant:)[\s\S]((?:\s.+)*)',
        'registrant_address':                  '(?<=[**] Administrative Contact)[\s\S]*?Address\s+: (.*)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.tr'
        self.update_reg_expressions(self._tr_expressions)


class RegexIS(BaseParser):

    _is_expressions = {
        'registrant_name':  'registrant: *(.+)',
        'registrant_address':          'address\.*: *(.+)',
        'created':    'created\.*: *(.+)',
        'expires':  'expires\.*: *(.+)',
        'dnssec':           'dnssec\.*: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.isnic.is'
        self.update_reg_expressions(self._is_expressions)


class RegexDK(BaseParser):

    _dk_expressions = {
        'created':       'Registered: *(.+)',
        'expires':     'Expires: *(.+)',
        'dnssec':              'Dnssec: *(.+)',
        'status':              'Status: *(.+)',
        'registrant_name':     'Registrant\s*(?:.*\n){2}\s*Name: *(.+)',
        'registrant_address':  'Registrant\s*(?:.*\n){3}\s*Address: *(.+)',
        'registrant_zipcode': 'Registrant\s*(?:.*\n){4}\s*Postalcode: *(.+)',
        'registrant_city':     'Registrant\s*(?:.*\n){5}\s*City: *(.+)',
        'registrant_country':  'Registrant\s*(?:.*\n){6}\s*Country: *(.+)',
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
        'expires':    'validity: *(.+)',
        'registrant_name':    'person: *(.+)',
        'registrant_address': 'address *(.+)',
        'dnssec':             'DNSSEC: *(.+)',
        'status':             'status: *(.+)',
        'registrar':          'registrar name: *(.+)',
        'referral_url':       'registrar info: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.isoc.org.il'
        self.update_reg_expressions(self._li_expressions)


class RegexIN(BaseParser):

    _in_expression = {
        'registrar':        'Registrar: *(.+)',
        'updated':          'Updated Date: (\d{4}-\d{2}-\d{2})',
        'created':          'Creation Date: (\d{4}-\d{2}-\d{2})',
        'expires':          'Registry Expiry Date: (\d{4}-\d{2}-\d{2})',
        'name_servers':     'Name Server: *(.+)',
        'organization':     'Registrant Organization: *(.+)',
        'registrant_state':            'Registrant State/Province: *(.+)',
        'status':           'Status: *(.+)',
        'registrant_country':          'Registrant Country: *(.+)',
        'dnssec':           'DNSSEC: *([\S]+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.registry.in'
        self.update_reg_expressions(self._in_expression)


class RegexCAT(BaseParser):

    _cat_expressions = {
        'registrar':        'Registrar: *(.+)',
        'updated':     'Updated Date: *(.+)',
        'created':    'Creation Date: *(.+)',
        'expires':  'Registry Expiry Date: *(.+)',
        'status':           'Domain status: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.cat'
        self.update_reg_expressions(self._cat_expressions)


class RegexIE(BaseParser):

    _ie_expressions = {
        'registrant_name':       'Domain Holder: *(.+)',
        'description':      'descr: *(.+)',
        'source':           'Source: *(.+)',
        'created':    'Registration Date: *(.+)',
        'expires':  'Renewal Date: *(.+)',
        'name_servers':     'Nserver: *(.+)',
        'status':           'Renewal status: *(.+)',
        'registrar':        'Account Name: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.iedr.ie'
        self.update_reg_expressions(self._ie_expressions)


class RegexNZ(BaseParser):

    _nz_expressions = {
        'registrar':            'registrar_name:\s*([^\n\r]+)',
        'updated':         'domain_datelastmodified:\s*([^\n\r]+)',
        'created':        'domain_dateregistered:\s*([^\n\r]+)',
        'expires':      'domain_datebilleduntil:\s*([^\n\r]+)',
        'name_servers':         'ns_name_\d*:\s*([^\n\r]+)',  
        'status':               'status:\s*([^\n\r]+)',  
        'registrant_name':                 'registrant_contact_name:\s*([^\n\r]+)',
        'registrant_address':              'registrant_contact_address\d*:\s*([^\n\r]+)',
        'registrant_city':                 'registrant_contact_city:\s*([^\n\r]+)',
        'registrant_zipcode':              'registrant_contact_postalcode:\s*([^\n\r]+)',
        'registrant_country':              'registrant_contact_country:\s*([^\n\r]+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.srs.net.nz'
        self.update_reg_expressions(self._nz_expressions)


class RegexLU(BaseParser):

    _lu_expressions = {
        'created':                  'registered: *(.+)',
        'name_servers':             'nserver: *(.+)',
        'status':                   'domaintype: *(.+)',
        'registrar':                'registrar-name: *(.+)',
        'registrant_organization':  'org-name: *(.+)',
        'registrant_address':       'org-address: *(.+)',
        'registrant_zipcode':       'org-zipcode:*(.+)',
        'registrant_city':          'org-city: *(.+)',
        'registrant_country':       'org-country: *(.+)',
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
        'registrant_name':  'registrant: *(.+)',
        'registrar':        'registrar: *(.+)',
        'created':          'registered: *(.+)',
        'updated':          'changed: *(.+)',
        'expires':          'expire: *(.+)',
        'name_servers':     'nserver: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.cz'
        self.update_reg_expressions(self._cz_expressions)


class RegexONLINE(BaseParser):

    _online_expressions = {
        'registrar':              'Registrar: *(.+)',
        'status':                 'Domain Status: *(.+)',
        'registrant_name':        'Registrant Email: *(.+)',
        # 'admin_email':          'Admin Email: *(.+)',
        # 'billing_email':        'Billing Email: *(.+)',
        # 'tech_email':           'Tech Email: *(.+)',
        'name_servers':           'Name Server: *(.+)',
        'created':                'Creation Date: *(.+)',
        'expires':                'Registry Expiry Date: *(.+)',
        'updated':                'Updated Date: *(.+)',
        'dnssec':                 'DNSSEC: *([\S]+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.online'
        self.update_reg_expressions(self._online_expressions)


class RegexHR(BaseParser):

    _hr_expressions = {
        'domain_name':           'Domain Name: *(.+)',
        'updated':               'Updated Date: *(.+)',
        'created':               'Creation Date: *(.+)',
        'expires':               'Registrar Registration Expiration Date: *(.+)',
        'name_servers':          'Name Server: *(.+)',
        'registrant_name':       'Registrant Name:\s(.+)',
        'registrant_address':    'Registrant Street:\s*(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.dns.hr'
        self.update_reg_expressions(self._hr_expressions)


class RegexHK(BaseParser):

    _hk_expressions = {
        'status':                 'Domain Status: *(.+)',
        'dnssec':                 'DNSSEC: *(.+)',
        'registrar':              'Registrar Name: *(.+)',
        'registrant_name':        'Registrant Contact Information:\s*Company English Name.*:(.+)',
        'registrant_address':     '(?<=Registrant Contact Information:)[\s\S]*?Address: (.*)',
        'registrant_country':     '[Registrant Contact Information\w\W]+Country: ([\S\ ]+)',
        'registrant_email':       '[Registrant Contact Information\w\W]+Email: ([\S\ ]+)',
        'updated':                'Updated Date: *(.+)',
        'created':                '[Registrant Contact Information\w\W]+Domain Name Commencement Date: (.+)',
        'expires':                '[Registrant Contact Information\w\W]+Expiry Date: (.+)',
        'name_servers':           'Name Servers Information:\s+((?:.+\n)*)'

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
        'domain_name':                   'domain: *(.+)',
        'status':                        'status: *(.+)',
        'registrar':                     '(?<=Registrar:)[\s\W\w]*?organization-loc:(.*)',
        'registrar_name':                '(?<=Registrar:)[\s\W\w]*?registrar:(.*)',
        'registrar_url':                 '(?<=Registrar:)[\s\W\w]*?url:(.*)',
        'registrar_country':             '(?<=Registrar:)[\s\W\w]*?country:(.*)',
        'registrar_city':                '(?<=Registrar:)[\s\W\w]*?city:\s+(.*)\n',
        'registrar_address':             '(?<=Registrar:)[\s\W\w]*?abuse-postal:\s+(.*)\n',
        'registrant_name':               '(?<=Registrant:)[\s\W\w]*?organization-loc:(.*)',
        'registrant_country':            '(?<=Registrant:)[\s\W\w]*?country-loc:(.*)',
        'registrant_city':               '(?<=Registrant:)[\s\W\w]*?(?:address\-loc:\s+.*\n){2}address-loc:\s+(.*)\n',
        'registrant_state':              '(?<=Registrant:)[\s\W\w]*?(?:address\-loc:\s+.*\n){1}address-loc:\s+(.*)\n',
        'registrant_address':            '(?<=Registrant:)[\s\W\w]*?address-loc:\s+(.*)\n',
        'registrant_zipcode':            '(?<=Registrant:)[\s\W\w]*?postal-code-loc:(.*)',
        'updated':                       'modified: *(.+)',
        'created':                       'created: (.+)',
        'expires':                       'expires: (.+)',
        'name_servers':                  'nserver: *(.+)'
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
        'status':                   'Domain Status: *(.+)',
        'registrar':                'Registrar: *(.+)',
        'registrant_name':          'Registrant Name: (.+)',
        'registrant_organization':  'Registrant Organization: (.+)',
        'registrant_city':          'Registrant City: (.*)',
        'registrant_address':       'Registrant Street: (.*)',
        'registrant_state':         'Registrant State/Province: (.*)',
        'registrant_zipcode':       'Registrant Postal Code: (.*)',
        'registrant_country':       'Registrant Country: (.+)',
        'registrant_phone':         'Registrant Phone: (.+)',
        'registrant_fax':           'Registrant Fax: (.+)',
        'registrant_email':         'Registrant Email: (.+)',
        'updated':                  'Updated Date: *(.+)',
        'created':                  'Creation Date: *(.+)',
        'expires':                  'Registry Expiry Date: *(.+)',
        'name_servers':             'Name Server: *(.+)'
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
        'status': 'Domain Status: *(.+)',
        'registrar': 'Registrar: *(.+)',
        'registrant_name': 'Registrant Name: (.+)',
        'registrant_organization': 'Registrant Organization: (.+)',
        'registrant_city': 'Registrant City: (.*)',
        'registrant_address': 'Registrant Street: (.*)',
        'registrant_state': 'Registrant State/Province: (.*)',
        'registrant_zipcode': 'Registrant Postal Code: (.*)',
        'registrant_country': 'Registrant Country: (.+)',
        'registrant_phone': 'Registrant Phone: (.+)',
        'registrant_fax': 'Registrant Fax: (.+)',
        'registrant_email': 'Registrant Email: (.+)',
        'updated': 'Updated Date: *(.+)',
        'created': 'Creation Date: *(.+)',
        'expires': 'Registry Expiry Date: *(.+)',
        'name_servers': 'Name Server: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.lat'
        self.update_reg_expressions(self._lat_expressions)


class RegexCN(BaseParser):

    _cn_expressions = {
        'registrar':            'Registrar: *(.+)',
        'created':        'Registration Time: *(.+)',
        'expires':      'Expiration Time: *(.+)',
        'name_servers':         'Name Server: *(.+)',  
        'status':               'Status: *(.+)',  
        'dnssec':               'dnssec: *([\S]+)',
        'registrant_name':                 'Registrant: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.cnnic.cn'
        self.update_reg_expressions(self._cn_expressions)


class RegexAPP(BaseParser):

    _app_expressions = {
        'registrar':            'Registrar: *(.+)',
        'updated':         'Updated Date: *(.+)',
        'created':        'Creation Date: *(.+)',
        'expires':      'Expir\w+ Date: *(.+)',
        'name_servers':         'Name Server: *(.+)',  
        'status':               'Status: *(.+)',  
        'dnssec':               'dnssec: *([\S]+)',
        'registrant_name':                 'Registrant Name: *(.+)',
        'registrant_organization':                  'Registrant\s*Organization: *(.+)',
        'registrant_address':              'Registrant Street: *(.+)',
        'registrant_city':                 'Registrant City: *(.+)',
        'registrant_state':                'Registrant State/Province: *(.+)',
        'registrant_zipcode':              'Registrant Postal Code: *(.+)',
        'registrant_country':              'Registrant Country: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.google'
        self.update_reg_expressions(self._app_expressions)


class RegexMONEY(BaseParser):

    _money_expressions = {
        'domain_name':          'Domain Name: *(.+)',
        'registrar':            'Registrar: *(.+)',
        'updated':         'Updated Date: *(.+)',
        'created':        'Creation Date: *(.+)',
        'expires':      'Registry Expiry Date: *(.+)',
        'name_servers':         'Name Server: *(.+)',  
        'status':               'Domain Status: *(.+)',
        'dnssec':               'DNSSEC: *(.+)',
        'registrant_name':                 'Registrant Name: *(.+)',
        'registrant_organization':         'Registrant Organization: *(.+)',
        'registrant_address':              'Registrant Street: *(.+)',
        'registrant_city':                 'Registrant City: *(.+)',
        'registrant_state':                'Registrant State/Province: *(.+)',
        'registrant_zipcode':              'Registrant Postal Code: *(.+)',
        'registrant_country':              'Registrant Country: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.money'
        self.update_reg_expressions(self._money_expressions)


class RegexAR(BaseParser):

    _ar_expressions = {
        'domain_name': 'domain: *(.+)',
        'registrar': 'registrar: *(.+)',
        'whois_server': 'whois: *(.+)',
        'updated': 'changed: *(.+)',
        'created': 'created: *(.+)',
        'expires': 'expire: *(.+)',
        'name_servers': 'nserver: *(.+) \(.*\)',
        'status': 'Domain Status: *(.+)',
        'registrant_name': 'name: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.ar'
        self.update_reg_expressions(self._ar_expressions)


class RegexBY(BaseParser):

    _by_expressions = {
        'domain_name': 'Domain Name: *(.+)',
        'registrar': 'Registrar: *(.+)',
        'updated': 'Updated Date: *(.+)',
        'created': 'Creation Date: *(.+)',
        'expires': 'Expiration Date: *(.+)',
        'name_servers': 'Name Server: *(.+)',
        'status': 'Domain Status: *(.+)',
        'registrant_name': 'Person: *(.+)',
        'registrant_organization': 'Org: *(.+)',
        'registrant_country': 'Country: *(.+)',
        'registrant_address': 'Address: *(.+)',
        'registrant_phone': 'Phone: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.cctld.by'
        self.update_reg_expressions(self._by_expressions)


class RegexCR(BaseParser):

    _cr_expressions = {
        'domain_name': 'domain: *(.+)',
        'registrant_name': 'registrant: *(.+)',
        'registrar': 'registrar: *(.+)',
        'updated': 'changed: *(.+)',
        'created': 'registered: *(.+)',
        'expires': 'expire: *(.+)',
        'name_servers': 'nserver: *(.+)',
        'status': 'status: *(.+)',
        'registrant_organization': 'org: *(.+)',
        'registrant_address': 'address: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.cr'
        self.update_reg_expressions(self._cr_expressions)


class RegexVE(BaseParser):

    _ve_expressions = {
        'domain_name': 'Nombre de Dominio: *(.+)',
        'status': 'Estatus del dominio: *(.+)',
        'registrar': 'registrar: *(.+)',
        'updated': 'Ultima Actualización: *(.+)',
        'created': 'Fecha de Creación: *(.+)',
        'expires': 'Fecha de Vencimiento: *(.+)',
        'name_servers': 'Nombres de Dominio:((?:\s+- .*)*)',
        'registrant_name': 'Titular:\s*(?:.*\n){1}\s+(.*)',
        'registrant_city': 'Titular:\s*(?:.*\n){3}\s+([\s\w]*)',
        'registrant_address': 'Titular:\s*(?:.*\n){2}\s+(.*)',
        'registrant_state': 'Titular:\s*(?:.*\n){3}\s+.*?,(.*),',
        'registrant_country': 'Titular:\s*(?:.*\n){3}\s+.*, .+  (.*)',
        'registrant_phone': 'Titular:\s*(?:.*\n){4}\s+(\+*\d.+)',
        'registrant_email': 'Titular:\s*.*\t(.*)',
    }

        # 'tech':                  'Contacto Técnico:\s*(?:.*\n){1}\s+(.*)',
        # 'tech_city':             'Contacto Técnico:\s*(?:.*\n){3}\s+([\s\w]*)',
        # 'tech_street':           'Contacto Técnico:\s*(?:.*\n){2}\s+(.*)',
        # 'tech_state_province':   'Contacto Técnico:\s*(?:.*\n){3}\s+.*?,(.*),',
        # 'tech_country':          'Contacto Técnico:\s*(?:.*\n){3}\s+.*, .+  (.*)',
        # 'tech_phone':            'Contacto Técnico:\s*(?:.*\n){4}\s+(\+*\d.*)\(',
        # 'tech_fax':              'Contacto Técnico:\s*(?:.*\n){4}\s+.*\(FAX\) (.*)',
        # 'tech_email':            'Contacto Técnico:\s*.*\t(.*)',
        # 'admin':                  'Contacto Administrativo:\s*(?:.*\n){1}\s+(.*)',
        # 'admin_city':             'Contacto Administrativo:\s*(?:.*\n){3}\s+([\s\w]*)',
        # 'admin_street':           'Contacto Administrativo:\s*(?:.*\n){2}\s+(.*)',
        # 'admin_state_province':   'Contacto Administrativo:\s*(?:.*\n){3}\s+.*?,(.*),',
        # 'admin_country':          'Contacto Administrativo:\s*(?:.*\n){3}\s+.*, .+  (.*)',
        # 'admin_phone':            'Contacto Administrativo:\s*(?:.*\n){4}\s+(\+*\d.*)\(',
        # 'admin_fax':              'Contacto Administrativo:\s*(?:.*\n){4}\s+.*\(FAX\) (.*)',
        # 'admin_email':            'Contacto Administrativo:\s*.*\t(.*)',
        # 'billing':                'Contacto de Cobranza:\s*(?:.*\n){1}\s+(.*)',
        # 'billing_city':           'Contacto de Cobranza:\s*(?:.*\n){3}\s+([\s\w]*)',
        # 'billing_street':         'Contacto de Cobranza:\s*(?:.*\n){2}\s+(.*)',
        # 'billing_state_province': 'Contacto de Cobranza:\s*(?:.*\n){3}\s+.*?,(.*),',
        # 'billing_country':        'Contacto de Cobranza:\s*(?:.*\n){3}\s+.*, .+  (.*)',
        # 'billing_phone':          'Contacto de Cobranza:\s*(?:.*\n){4}\s+(\+*\d.*)\(',
        # 'billing_fax':            'Contacto de Cobranza:\s*(?:.*\n){4}\s+.*\(FAX\) (.*)',
        # 'billing_email':          'Contacto de Cobranza:\s*.*\t(.*)',

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.ve'
        self.update_reg_expressions(self._ve_expressions)


class RegexDO(BaseParser):

    _do_expressions = {
        'registrar':            'Registrar: *(.+)',
        'registrar_email':      'Registrar Customer Service Email: *(.+)',
        'registrar_phone':      'Registrar Phone: *(.+)',
        'registrar_address':    'Registrar Address: *(.+)',
        'registrar_country':    'Registrar Country: *(.+)',
        'status':               'Domain Status: *(.+)',  
        'registrant_id':        'Registrant ID: *(.+)',
        'registrant_name':      'Registrant Name: *(.+)',
        'registrant_organization': 'Registrant Organization: *(.+)',
        'registrant_address':   'Registrant Street: *(.+)',
        'registrant_city':      'Registrant City: *(.+)',
        'registrant_state': 'Registrant State/Province: *(.+)',
        'registrant_zipcode': 'Registrant Postal Code: *(.+)',
        'registrant_country': 'Registrant Country: *(.+)',
        'registrant_phone_number': 'Registrant Phone: *(.+)',
        'registrant_email':     'Registrant Email: *(.+)',
        'admin_id':             'Admin ID: *(.+)',
        'admin_name':           'Admin Name: *(.+)',
        'admin_organization':   'Admin Organization: *(.+)',
        'admin_address':        'Admin Street: *(.+)',
        'admin_city':           'Admin City: *(.+)',
        'admin_state_province': 'Admin State/Province: *(.+)',
        'admin_postal_code':    'Admin Postal Code: *(.+)',
        'admin_country':        'Admin Country: *(.+)',
        'admin_phone_number':   'Admin Phone: *(.+)',
        'admin_email':          'Admin Email: *(.+)',
        'billing_id':           'Billing ID: *(.+)',
        'billing_name':         'Billing Name: *(.+)',
        'billing_address':      'Billing Street: *(.+)',
        'billing_city':         'Billing City: *(.+)',
        'billing_state_province': 'Billing State/Province: *(.+)',
        'billing_postal_code':  'Billing Postal Code: *(.+)',
        'billing_country':      'Billing Country: *(.+)',
        'billing_phone_number': 'Billing Phone: *(.+)',
        'billing_email':        'Billing Email: *(.+)',
        'tech_id':              'Tech ID: *(.+)',
        'tech_name':            'Tech Name: *(.+)',
        'tech_organization':    'Tech Organization: *(.+)',
        'tech_address':         'Tech Street: *(.+)',
        'tech_city':            'Tech City: *(.+)',
        'tech_state_province':  'Tech State/Province: *(.+)',
        'tech_postal_code':     'Tech Postal Code: *(.+)',
        'tech_country':         'Tech Country: *(.+)',
        'tech_phone_number':    'Tech Phone: *(.+)',
        'tech_email':           'Tech Email: *(.+)',
        'name_servers':         'Name Server: *(.+)',  
        'created':        'Creation Date: *(.+)',
        'expires':      'Registry Expiry Date: *(.+)',
        'updated':         'Updated Date: *(.+)',
        'dnssec':               'DNSSEC: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.do'
        self.update_reg_expressions(self._do_expressions)


class RegexAE(BaseParser):

    _ae_expressions = {
        'status':          'Status: *(.+)',
        'registrant_name': 'Registrant Contact Name: *(.+)',
        'tech_name':       'Tech Contact Name: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.aeda.net.ae'
        self.update_reg_expressions(self._ae_expressions)


class RegexSI(BaseParser):

    _si_expressions = {
        'registrar':       'registrar: *(.+)',
        'name_servers':    'nameserver: *(.+)',
        'registrant_name': 'registrant: *(.+)',
        'created':   'created: *(.+)',
        'expires': 'expire: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.register.si'
        self.update_reg_expressions(self._si_expressions)


class RegexNO(BaseParser):

    _no_expressions = {
        'created':   'Additional information:\nCreated:\s*(.+)',
        'updated':    'Additional information:\n(?:.*\n)Last updated:\s*(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.norid.no'
        self.update_reg_expressions(self._no_expressions)


class RegexKZ(BaseParser):

    _kz_expressions = {
        'registar_created': 'Registar Created: *(.+)', # TYPOS are on the whois server
        'registrar': 'Current Registar: *(.+)', # TYPOS are on the whois server
        'created':    'Domain created: *(.+)',
        'updated': 'Last modified : *(.+)',
        'name_servers':     'server.*: *(.+)',  
        'status':           ' (.+?) -',  
        'registrant_organization':              'Organization Name.*: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.kz'
        self.update_reg_expressions(self._kz_expressions)


class RegexTOP(BaseParser):

    _top_expressions = {
        'expires': 'Registrar Registration Expiration Date: (\d{4}-\d{2}-\d{2})'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.top'
        self.update_reg_expressions(self._top_expressions)


class RegexIR(BaseParser):

    _ir_expressions = {
        'updated': 'last-updated: *(.+)',
        'expires': 'expire-date: *(.+)'
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
        'created': 'Creation Date: (\d{4}-\d{2}-\d{2})',
        'updated': 'Updated Date: (\d{4}-\d{2}-\d{2})',
        'expires': 'Registrar Registration Expiration Date: (\d{4}-\d{2}-\d{2})'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.icu'
        self.update_reg_expressions(self._icu_expressions)


class RegexTK(BaseParser):

    _tk_expressions = {
        'created': 'Domain registered: *(.+)',
        'expires': 'Record will expire on: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.dot.tk'
        self.update_reg_expressions(self._tk_expressions)
