from typing import Dict, Any, Union, List
import datetime
import re
from enum import Enum

from .errors import WhoIsQueryParserError

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
    '%Y-%m-%d %H:%M:%S.%f',     # 23/04/2015 12:00:07.619546
    '%B %d %Y',                 # August 14 2017
    '%d.%m.%Y %H:%M:%S',        # 08.03.2014 10:28:24
    '%a %b %d %Y',              # Tue Dec 12 2000
]


class BaseKeys(str, Enum):
    DOMAIN_NAME             = 'domain_name'

    CREATED                 = 'created'
    UPDATED                 = 'updated'
    EXPIRES                 = 'expires'

    REGISTRAR               = 'registrar'

    REGISTRANT_NAME         = 'registrant_name'
    REGISTRANT_ORGANIZATION = 'registrant_organization'
    REGISTRANT_ADDRESS      = 'registrant_address'
    REGISTRANT_CITY         = 'registrant_city'
    REGISTRANT_STATE        = 'registrant_state'
    REGISTRANT_COUNTRY      = 'registrant_country'
    REGISTRANT_ZIPCODE      = 'registrant_zipcode'

    DNSSEC                  = 'dnssec'
    STATUS                  = 'status'
    NAME_SERVERS            = 'name_servers'

    def __repr__(self):
        return self.value

    def __str__(self):
        return self.value


class BaseParser:
    base_expressions = {
        BaseKeys.DOMAIN_NAME             : r'Domain Name: *(.+)',

        BaseKeys.CREATED                 : r'Creation Date: *(.+)',
        BaseKeys.UPDATED                 : r'Updated Date: *(.+)',
        BaseKeys.EXPIRES                 : r'Expir\w+\sDate: *(.+)',

        BaseKeys.REGISTRAR               : r'Registrar: *(.+)',

        BaseKeys.REGISTRANT_NAME         : r'Registrant Name: *(.+)',
        BaseKeys.REGISTRANT_ORGANIZATION : r'Registrant Organization: *(.+)',
        BaseKeys.REGISTRANT_ADDRESS      : r'Registrant Street: *(.+)',
        BaseKeys.REGISTRANT_CITY         : r'Registrant City: *(.+)',
        BaseKeys.REGISTRANT_STATE        : r'Registrant State/Province: *(.+)',
        BaseKeys.REGISTRANT_ZIPCODE      : r'Registrant Postal Code: *(.+)',
        BaseKeys.REGISTRANT_COUNTRY      : r'Registrant Country: *(.+)',

        BaseKeys.DNSSEC                  : r'DNSSEC: *([\S]+)',
        BaseKeys.STATUS                  : r'Status: *(.+)',
        BaseKeys.NAME_SERVERS            : r'Name server: *(.+)'

        # todo: A future PR will include information beyond "Registrant"
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

    multiple_match_keys = (BaseKeys.NAME_SERVERS, BaseKeys.STATUS)
    date_keys = (BaseKeys.CREATED, BaseKeys.UPDATED, BaseKeys.EXPIRES)

    def __init__(self):
        self.server = None
        self.reg_expressions = {}

    def update_reg_expressions(self, expressions_update: Dict[str, Any]) -> None:
        """
        Updates the `reg_expressions` dictionary
        :param expressions_update: dictionary of keys/regexes to update
        """
        expressions = self.base_expressions.copy()
        expressions.update(expressions_update)
        self.reg_expressions = expressions

    def parse(self, blob: str) -> Dict[str, Any]:
        """
        Iterates over the `reg_expressions` dictionary attempting to use each regex to extract values
        from `blob`, the output from the whois server.

        Assumes that the keys and regular expressions are formatted in the output `blob` such
        that a re.findall operation will work correctly. If this is not the case, you should implement
        your own version of this function in the appropriate BaseParser child class.

        :param blob: the output from the whois server
        :return: dictionary of parsed key/value pairs
        """
        parsed_output = {}
        for key, regex in self.reg_expressions.items():
            if not regex:
                parsed_output[key] = None
            else:
                many = key in self.multiple_match_keys
                parsed_output[key] = self.find_match(regex, blob, many=many)
                if key in self.date_keys and parsed_output.get(key, None):
                    parsed_output[key] = self._parse_date(parsed_output.get(key))
        return parsed_output

    def find_match(self, regex: str, blob: str, flags: re.RegexFlag = re.IGNORECASE,
                   many: bool = False) -> Union[str, List[str], None]:
        """
        Performs the given regex operation on the raw output `blob`

        :param regex: the regex to use against blob
        :param blob: the raw output from the whois server
        :param flags: the optional flags to pass to the `re` method
        :param many: if True this function will use re.findall for many matches else re.search for single match
        """
        if many:
            matches = re.findall(regex, blob, flags=flags)
            return [self._process(m) for m in matches if m]
        else:
            match = re.search(regex, blob, flags=flags)
            if match:
                return self._process(match.group(1))
            return None

    @staticmethod
    def _parse_date(date_string: str) -> Union[datetime.datetime, str]:
        """
        Attempts to convert the given date string to a datetime.datetime object
        otherwise returns the input `date_string`
        :param date_string: a date string
        :return: a datetime.datetime object
        """
        for date_format in KNOWN_DATE_FORMATS:
            try:
                date = datetime.datetime.strptime(date_string, date_format)
                return date
            except ValueError:
                continue
        return date_string

    def _process_many(self, match: str) -> List[str]:
        if '\n' in match:
            match = match.split('\n')
            return [self._process(m) for m in match if m]
        else:
            return [self._process(match)]

    @staticmethod
    def _process(match: str) -> str:
        if match:
            return match.rstrip('\r').rstrip('\n').lstrip('\t').lstrip().rstrip()


class WhoIsParser:

    def __init__(self, top_level_domain: str):
        self.parser_output = {}
        self._parser = self._init_parser(top_level_domain)

    def parse(self, blob: str) -> None:
        no_match_checks = ['no match', 'not found', 'no entries found']
        if any([n in blob.lower() for n in no_match_checks]):
            raise WhoIsQueryParserError(f'Domain not found!')
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
        elif tld == 'cc':
            return RegexCC()
        elif tld == 'ch':
            return RegexCH()
        elif tld == 'cl':
            return RegexCL()
        elif tld == 'club':
            return RegexClub()
        elif tld == 'cn':
            return RegexCN()
        elif tld == 'co':
            return RegexCO()
        elif tld == 'com':
            return RegexCOM()
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
        elif tld == 'edu':
            return RegexEDU()
        elif tld == 'ee':
            return RegexEE()
        elif tld == 'eu':
            return RegexEU()
        elif tld == 'fi':
            return RegexFI()
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
        elif tld == 'sa':
            return RegexSA()
        elif tld == 'se':
            return RegexSE()
        elif tld == 'si':
            return RegexSI()
        elif tld == 'sk':
            return RegexSK()
        elif tld == 'space':
            return RegexSPACE()
        elif tld == 'su':
            return RegexSU()
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
        elif tld == 'xyz':
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

    _net_expressions = {}

    def __init__(self):
        super().__init__()
        self.server = 'whois.verisign-grs.com'
        self.update_reg_expressions(self._net_expressions)


class RegexORG(BaseParser):

    _org_expressions = {}

    def __init__(self):
        super().__init__()
        self.server = 'whois.pir.org'
        self.update_reg_expressions(self._org_expressions)


class RegexRU(BaseParser):

    _ru_expressions = {
        BaseKeys.CREATED                : r'created: *(.+)',
        BaseKeys.EXPIRES                : r'paid-till: *(.+)',
        BaseKeys.REGISTRANT_ORGANIZATION: r'org: *(.+)',
        BaseKeys.STATUS                 : r'state: *(.+)',
        BaseKeys.NAME_SERVERS           : r'nserver: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.tcinet.ru'
        self.update_reg_expressions(self._ru_expressions)


class RegexCL(BaseParser):

    _cl_expressions = {
        BaseKeys.NAME_SERVERS           : r'Name server: *(.+)',
        BaseKeys.REGISTRANT_NAME        : r'Registrant name: *(.+)',
        BaseKeys.REGISTRANT_ORGANIZATION: r'Registrant organisation: *(.+)',
        BaseKeys.REGISTRAR              : r'Registrar name: *(.+)',
        BaseKeys.EXPIRES                : r'Expiration date: (\d{4}-\d{2}-\d{2})',
        BaseKeys.CREATED                : r'Creation date: (\d{4}-\d{2}-\d{2})',
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
        BaseKeys.DOMAIN_NAME    : r'DOMAIN NAME: *(.+)\n',
        BaseKeys.NAME_SERVERS   : r'nameservers:(.*?)created',
        BaseKeys.REGISTRAR      : r'REGISTRAR:\s*(.+)',
        BaseKeys.CREATED        : r'created: *(.+)',
        BaseKeys.EXPIRES        : r'option expiration date: *(.+)',
        BaseKeys.UPDATED        : r'last modified: *(.+)\n',
        BaseKeys.DNSSEC         : r'dnssec: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.dns.pl'
        self.update_reg_expressions(self._pl_expressions)

    def parse(self, blob: str) -> Dict[str, Any]:
        parsed_output = {}
        for key, regex in self.reg_expressions.items():
            if key == BaseKeys.NAME_SERVERS:
                match = self.find_match(regex, blob, flags=re.DOTALL|re.IGNORECASE, many=False)
                parsed_output[BaseKeys.NAME_SERVERS] = [self._process(m) for m in match.split('\n')]
            else:
                many = key in self.multiple_match_keys
                parsed_output[key] = self.find_match(regex, blob, many=many)
                if key in self.date_keys and parsed_output.get(key, None):
                    parsed_output[key] = self._parse_date(parsed_output.get(key))

        return parsed_output


class RegexRO(BaseParser):
    # % The ROTLD WHOIS service on port 43 never discloses any information concerning the registrant.

    _ro_expressions = {
        BaseKeys.CREATED        : r'Registered On: *(.+)',
        BaseKeys.EXPIRES        : r'Expires On: *(.+)',
        BaseKeys.NAME_SERVERS   : r'Nameserver: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.rotld.ro'
        self.update_reg_expressions(self._ro_expressions)


class RegexPE(BaseParser):

    _pe_expressions = {
        BaseKeys.REGISTRANT_NAME: r'Registrant name: *(.+)',
        BaseKeys.REGISTRAR      : r'Sponsoring Registrar: *(.+)',
        BaseKeys.DNSSEC         : r'DNSSEC: *(.+)',
        BaseKeys.NAME_SERVERS   : r'Name server: *(.+)',
        BaseKeys.STATUS         : r'Domain Status: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'kero.yachay.pe'
        self.update_reg_expressions(self._pe_expressions)


class RegexSPACE(BaseParser):

    _space_expressions = {}

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
        BaseKeys.DOMAIN_NAME        : r'Domain: *[\n\r]+\s*name: *([^\n\r]+)',
        BaseKeys.STATUS             : r'status: *([^\n\r]+)',
        BaseKeys.CREATED            : r'registered: *([^\n\r]+)',
        BaseKeys.UPDATED            : r'changed: *([^\n\r]+)',
        BaseKeys.EXPIRES            : r'expire: *([^\n\r]+)',
        BaseKeys.REGISTRAR          : r'Registrar: *[\n\r]+\s*name: *([^\n\r]+)',
        BaseKeys.NAME_SERVERS       : r'nserver: *(.*)',
        BaseKeys.REGISTRANT_COUNTRY : r'country: *(.+)'
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
        BaseKeys.CREATED: r'created: (\d{4}-\d{2}-\d{2})',
        BaseKeys.UPDATED: r'last-update: (\d{4}-\d{2}-\d{2})',
        BaseKeys.EXPIRES: r'Expiry Date: (\d{4}-\d{2}-\d{2})',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.fr'
        self.update_reg_expressions(self._fr_expressions)


class RegexBR(BaseParser):

    _br_expressions = {
        BaseKeys.CREATED: r'created: ',
        BaseKeys.UPDATED: r'changed: ',
        BaseKeys.STATUS: r'status: *(.+)',
        BaseKeys.REGISTRANT_NAME: r'responsible: *(.+)',
        BaseKeys.REGISTRANT_COUNTRY: r'country: *(.+)',
        BaseKeys.EXPIRES: r'expires: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.registro.br'
        self.update_reg_expressions(self._br_expressions)


class RegexKR(BaseParser):

    _kr_expressions = {
        BaseKeys.CREATED: r'Registered Date *: (\d{4}\.\s\d{2}\.\s\d{2}\.)',
        BaseKeys.UPDATED: r'Last Updated Date *: (\d{4}\.\s\d{2}\.\s\d{2}\.)',
        BaseKeys.EXPIRES: r'Expiration Date *: (\d{4}\.\s\d{2}\.\s\d{2}\.)',
        BaseKeys.REGISTRANT_NAME: r'Registrant *: (.+)',
        BaseKeys.DNSSEC: r'DNSSEC *: (.+)',
        BaseKeys.REGISTRANT_ZIPCODE: r'Registrant Zip Code: *: (.+)',
        BaseKeys.REGISTRANT_ADDRESS: r'Registrant Address *: (.+)'
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
        BaseKeys.REGISTRAR: r"Registrar:\nName: *(.+)",
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
        BaseKeys.UPDATED        : r'Changed: (\d{4}\.\s\d{2}\.\s\d{2}\.)',
        BaseKeys.NAME_SERVERS   : r'Nserver: *(.+)',
        BaseKeys.DOMAIN_NAME    : r'Domain: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.denic.de'
        self.update_reg_expressions(self._de_expressions)


class RegexUK(BaseParser):

    _uk_expressions = {
        BaseKeys.CREATED: r'Registered on:\s*(\d{2}-\w{3}-\d{4})',
        BaseKeys.UPDATED: r'Last updated:\s*(\d{2}-\w{3}-\d{4})',
        BaseKeys.EXPIRES: r'Expiry date:\s*(\d{2}-\w{3}-\d{4})',
        BaseKeys.REGISTRAR: r'Registrar:\s*(.+)',
        BaseKeys.NAME_SERVERS: r'Name servers:\s*(.+\s.+\s.+\s.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.uk'
        self.update_reg_expressions(self._uk_expressions)


class RegexJP(BaseParser):

    _jp_expressions = {
        BaseKeys.REGISTRANT_NAME: r'\[Registrant\] *(.+)',
        BaseKeys.CREATED: r'\[登録年月日\] *(.+)',
        BaseKeys.EXPIRES: r'\[有効期限\] *(.+)',
        BaseKeys.STATUS: r'\[状態\] *(.+)',
        BaseKeys.UPDATED: r'\[最終更新\] *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.jprs.jp'
        self.update_reg_expressions(self._jp_expressions)


class RegexAU(BaseParser):

    _au_expressions = {
        BaseKeys.UPDATED: r'Last Modified: (\d{2}-\w{3}-\d{4})',
        BaseKeys.REGISTRAR: r'Registrar Name:\s *(.+)',
        BaseKeys.REGISTRANT_NAME: r'Registrant: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.auda.org.au'
        self.update_reg_expressions(self._au_expressions)



class RegexAT(BaseParser):

    _at_expressions = {
        BaseKeys.REGISTRAR: r'registrar: *(.+)',
        BaseKeys.REGISTRANT_NAME: r'personname: *(.+)',
        BaseKeys.REGISTRANT_ADDRESS: r'street address: *(.+)',
        BaseKeys.REGISTRANT_ZIPCODE: r'postal code: *(.+)',
        BaseKeys.REGISTRANT_CITY: r'city: *(.+)',
        BaseKeys.REGISTRANT_COUNTRY: r'country: *(.+)',
        BaseKeys.UPDATED: r'changed: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.at'
        self.update_reg_expressions(self._at_expressions)


class RegexBE(BaseParser):

    _be_expressions = {
        BaseKeys.CREATED: r'Registered: *(.+)',
        BaseKeys.REGISTRAR: r'Registrar:\n.+Name:\t\s*(.+)',
        BaseKeys.NAME_SERVERS: r'Nameservers:\s*(.+\s.+\s.+\s.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.dns.be'
        self.update_reg_expressions(self._be_expressions)


class RegexINFO(BaseParser):

    _info_expressions = {
        BaseKeys.REGISTRAR:                   r'Registrar: *(.+)',
        BaseKeys.UPDATED:                     r'Updated Date: *(.+)',
        BaseKeys.CREATED:                     r'Creation Date: *(.+)',
        BaseKeys.EXPIRES:                     r'Registry Expiry Date: *(.+)',
        BaseKeys.STATUS:                      r'Status: *(.+)',
        BaseKeys.REGISTRANT_NAME:             r'Registrant Name: *(.+)',
        BaseKeys.REGISTRANT_ORGANIZATION:     r'Registrant Organization: *(.+)',
        BaseKeys.REGISTRANT_ADDRESS:          r'Registrant Street: *(.+)',
        BaseKeys.REGISTRANT_CITY:             r'Registrant City: *(.+)',
        BaseKeys.REGISTRANT_STATE:            r'Registrant State/Province: *(.+)',
        BaseKeys.REGISTRANT_ZIPCODE:          r'Registrant Postal Code: *(.+)',
        BaseKeys.REGISTRANT_COUNTRY:          r'Registrant Country: *(.+)',
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
        BaseKeys.REGISTRAR: r'Sponsoring Registrar: *(.+)',
        BaseKeys.STATUS: r'Domain Status: *(.+)',
        BaseKeys.REGISTRANT_NAME: r'Registrant Name: *(.+)',
        BaseKeys.REGISTRANT_CITY:    r'Registrant City: *(.+)',
        BaseKeys.REGISTRANT_STATE:   r'Registrant State/Province: *(.+)',
        BaseKeys.REGISTRANT_ZIPCODE: r'Registrant Postal Code: *(.+)',
        BaseKeys.REGISTRANT_COUNTRY: r'Registrant Country: *(.+)',
        BaseKeys.CREATED: r'Domain Registration Date: *(.+)',
        BaseKeys.EXPIRES: r'Domain Expiration Date: *(.+)',
        BaseKeys.UPDATED: r'Domain Last Updated Date: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.club'
        self.update_reg_expressions(self._club_expressions)


class RegexIO(BaseParser):

    _io_expressions = {}

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.io'
        self.update_reg_expressions(self._io_expressions)


class RegexBIZ(BaseParser):

    _biz_expressions = {}

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
        BaseKeys.REGISTRAR: r'Domain support: \s*(.+)',
        BaseKeys.REGISTRANT_NAME: r'Name: *(.+)',
        BaseKeys.REGISTRANT_ADDRESS: r'Address: *(.+)',
        BaseKeys.CREATED: r'Record created: *(.+)',
        BaseKeys.EXPIRES: r'Record expires on \s*(.+)',
        BaseKeys.UPDATED: r'Record last updated on\s*(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.kg'
        self.update_reg_expressions(self._kg_expressions)


class RegexCH(BaseParser):

    _ch_expressions = {
        BaseKeys.REGISTRANT_NAME: r'Holder of domain name:\s*(?:.*\n){1}\s*(.+)',
        BaseKeys.REGISTRANT_ADDRESS: r'Holder of domain name:\s*(?:.*\n){2}\s*(.+)',
        BaseKeys.REGISTRAR: r'Registrar:\n*(.+)',
        BaseKeys.CREATED: r'First registration date:\n*(.+)',
        BaseKeys.DNSSEC: r'DNSSEC:*([\S]+)',
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
        BaseKeys.CREATED: r'Created On:(.+)',
        BaseKeys.EXPIRES: r'Expiration Date:(.+)',
        BaseKeys.UPDATED: r'Last Updated On:(.+)',
        BaseKeys.DNSSEC: r'DNSSEC:(.+)',
        BaseKeys.REGISTRAR: r'Sponsoring Registrar Organization:(.+)',
        BaseKeys.STATUS: r'Status:(.+)',
        BaseKeys.REGISTRANT_NAME: r'Registrant Name:(.+)',
        BaseKeys.REGISTRANT_ADDRESS: r'Registrant Street1:(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.id'
        self.update_reg_expressions(self._id_expressions)


class RegexSE(BaseParser):

    _se_expressions = {
        BaseKeys.REGISTRANT_NAME: r'holder\.*: *(.+)',
        BaseKeys.CREATED: r'created\.*: *(.+)',
        BaseKeys.UPDATED: r'modified\.*: *(.+)',
        BaseKeys.EXPIRES: r'expires\.*: *(.+)',
        BaseKeys.DNSSEC: r'dnssec\.*: *(.+)',
        BaseKeys.STATUS: r'status\.*: *(.+)',
        BaseKeys.REGISTRAR: r'registrar: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.iis.se'
        self.update_reg_expressions(self._se_expressions)


class RegexJobs(BaseParser):

    _jobs_expressions = {}

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.jobs'
        self.update_reg_expressions(self._jobs_expressions)


class RegexIT(BaseParser):

    _it_expressions = {
        BaseKeys.DOMAIN_NAME: r'Domain: *(.+)',
        BaseKeys.CREATED: r'(?<! )Created: *(.+)',
        BaseKeys.UPDATED: r'(?<! )Last Update: *(.+)',
        BaseKeys.EXPIRES: r'(?<! )Expire Date: *(.+)',
        BaseKeys.STATUS: r'Status: *(.+)',
        BaseKeys.REGISTRANT_NAME: r'(?<=Registrant)[\s\S]*?Organization:(.*)',
        BaseKeys.REGISTRANT_ADDRESS: r'(?<=Registrant)[\s\S]*?Address:(.*)',
        BaseKeys.REGISTRAR: r'(?<=Registrar)[\s\S]*?Name:(.*)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.it'
        self.update_reg_expressions(self._it_expressions)


class RegexSA(BaseParser):

    _sa_expressions = {
        BaseKeys.CREATED: r'Created on: *(.+)',
        BaseKeys.UPDATED: r'Last Updated on: *(.+)',
        BaseKeys.REGISTRANT_NAME: r'Registrant:\s*(.+)',
        BaseKeys.REGISTRANT_ADDRESS: r'(?<=Registrant)[\s\S]*?Address:((?:.+\n)*)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.net.sa'
        self.update_reg_expressions(self._sa_expressions)


class RegexSK(BaseParser):

    _sk_expressions = {
        BaseKeys.CREATED: r'(?<=Domain:)[\s\w\W]*?Created: *(.+)',
        BaseKeys.UPDATED: r'(?<=Domain:)[\s\w\W]*?Updated: *(.+)',
        BaseKeys.EXPIRES: r'Valid Until: *(.+)',
        BaseKeys.REGISTRANT_NAME: r'Name:\s*(.+)',
        BaseKeys.REGISTRANT_ADDRESS: r'Street:\s*(.+)',
        BaseKeys.REGISTRAR: r'(?<=Registrar)[\s\S]*?Organization:(.*)',
        BaseKeys.REGISTRANT_CITY: r'(?<=^Contact)[\s\S]*?City:(.*)',
        BaseKeys.REGISTRANT_ZIPCODE: r'(?<=^Contact)[\s\S]*?Postal Code:(.*)',
        BaseKeys.REGISTRANT_COUNTRY: r'(?<=^Contact)[\s\S]*?Country Code:(.*)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.sk-nic.sk'
        self.update_reg_expressions(self._sk_expressions)


class RegexMX(BaseParser):

    _mx_expressions = {
        BaseKeys.CREATED: r'Created On: *(.+)',
        BaseKeys.UPDATED: r'Last Updated On: *(.+)',
        BaseKeys.EXPIRES: r'Expiration Date: *(.+)',
        BaseKeys.REGISTRAR: 'Registrar:\s*(.+)',
        BaseKeys.REGISTRANT_NAME: r'(?<=Registrant)[\s\S]*?Name:(.*)',
        BaseKeys.REGISTRANT_CITY: r'(?<=Registrant)[\s\S]*?City:(.*)',
        BaseKeys.REGISTRANT_STATE: r'(?<=Registrant)[\s\S]*?State:(.*)',
        BaseKeys.REGISTRANT_COUNTRY: r'(?<=Registrant)[\s\S]*?Country:(.*)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.mx'
        self.update_reg_expressions(self._mx_expressions)


class RegexTW(BaseParser):

    _tw_expressions = {
        BaseKeys.CREATED: r'Record created on (.+) ',
        BaseKeys.EXPIRES: r'Record expires on (.+) ',
        BaseKeys.REGISTRAR: r'Registration Service Provider: *(.+)',
        BaseKeys.REGISTRANT_NAME: r'(?<=Registrant:)\s+(.*)',
        BaseKeys.REGISTRANT_CITY: r'(?<=Registrant:)\s*(?:.*\n){5}\s+(.*),',
        BaseKeys.REGISTRANT_ADDRESS: r'(?<=Registrant:)\s*(?:.*\n){4}\s+(.*)',
        BaseKeys.REGISTRANT_STATE: r'(?<=Registrant:)\s*(?:.*\n){5}.*, (.*)',
        BaseKeys.REGISTRANT_COUNTRY: r'(?<=Registrant:)\s*(?:.*\n){6}\s+(.*)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.twnic.net.tw'
        self.update_reg_expressions(self._tw_expressions)


class RegexTR(BaseParser):

    _tr_expressions = {
        BaseKeys.CREATED: r'Created on.*: *(.+)',
        BaseKeys.EXPIRES: r'Expires on.*: *(.+)',
        BaseKeys.REGISTRANT_NAME: r'(?<=[**] Registrant:)[\s\S]((?:\s.+)*)',
        BaseKeys.REGISTRANT_ADDRESS: r'(?<=[**] Administrative Contact)[\s\S]*?Address\s+: (.*)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.tr'
        self.update_reg_expressions(self._tr_expressions)


class RegexIS(BaseParser):

    _is_expressions = {
        BaseKeys.REGISTRANT_NAME: r'registrant: *(.+)',
        BaseKeys.REGISTRANT_ADDRESS: r'address\.*: *(.+)',
        BaseKeys.CREATED: r'created\.*: *(.+)',
        BaseKeys.EXPIRES: r'expires\.*: *(.+)',
        BaseKeys.DNSSEC: r'dnssec\.*: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.isnic.is'
        self.update_reg_expressions(self._is_expressions)


class RegexDK(BaseParser):

    _dk_expressions = {
        BaseKeys.CREATED: r'Registered: *(.+)',
        BaseKeys.EXPIRES: r'Expires: *(.+)',
        BaseKeys.DNSSEC: r'Dnssec: *(.+)',
        BaseKeys.STATUS: r'Status: *(.+)',
        BaseKeys.REGISTRANT_NAME: r'Registrant\s*(?:.*\n){2}\s*Name: *(.+)',
        BaseKeys.REGISTRANT_ADDRESS: r'Registrant\s*(?:.*\n){3}\s*Address: *(.+)',
        BaseKeys.REGISTRANT_ZIPCODE: r'Registrant\s*(?:.*\n){4}\s*Postalcode: *(.+)',
        BaseKeys.REGISTRANT_CITY: r'Registrant\s*(?:.*\n){5}\s*City: *(.+)',
        BaseKeys.REGISTRANT_COUNTRY: r'Registrant\s*(?:.*\n){6}\s*Country: *(.+)',
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
        BaseKeys.EXPIRES: r'validity: *(.+)',
        BaseKeys.REGISTRANT_NAME: r'person: *(.+)',
        BaseKeys.REGISTRANT_ADDRESS: r'address *(.+)',
        BaseKeys.DNSSEC: r'DNSSEC: *(.+)',
        BaseKeys.STATUS: r'status: *(.+)',
        BaseKeys.REGISTRAR: r'registrar name: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.isoc.org.il'
        self.update_reg_expressions(self._li_expressions)


class RegexFI(BaseParser):

    _fi_expressions = {
        BaseKeys.DOMAIN_NAME: r'domain\.*: *([\S]+)',
        BaseKeys.REGISTRANT_NAME: r'Holder\s*name\.*:\s(.+)',
        BaseKeys.REGISTRANT_ADDRESS: r'[Holder\w\W]address\.*: ([\S\ ]+)',
        BaseKeys.REGISTRANT_ZIPCODE: r'[Holder\w\W]address\.*:.+\naddress\.*:\s(.+)',
        BaseKeys.REGISTRANT_CITY: r'[Holder\w\W]address\.*:.+\naddress\.*:.+\naddress\.*:\s(.+)',
        BaseKeys.REGISTRANT_COUNTRY: r'country\.*:\s(.+)',
        BaseKeys.STATUS: r'status\.*: *([\S]+)',
        BaseKeys.CREATED: r'created\.*: *([\S]+)',
        BaseKeys.UPDATED: r'modified\.*: *([\S]+)',
        BaseKeys.EXPIRES: r'expires\.*: *([\S]+)',
        BaseKeys.NAME_SERVERS: r'nserver\.*: *([\S]+) \[\S+\]',
        BaseKeys.DNSSEC: r'dnssec\.*: *([\S]+)',
        BaseKeys.REGISTRAR: r'registrar\.*:\s(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.fi'
        self.update_reg_expressions(self._fi_expressions)


class RegexNU(BaseParser):

    _nu_expression = {
        BaseKeys.DOMAIN_NAME: r'domain\.*: *(.+)',
        BaseKeys.REGISTRANT_NAME: r'holder\.*: *(.+)',
        BaseKeys.CREATED: r'created\.*: *(.+)',
        BaseKeys.UPDATED: r'modified\.*: *(.+)',
        BaseKeys.EXPIRES: r'expires\.*: *(.+)',
        BaseKeys.NAME_SERVERS: r'nserver\.*: *(.+)',
        BaseKeys.DNSSEC: r'dnssec\.*: *(.+)',
        BaseKeys.STATUS: r'status\.*: *(.+)',
        BaseKeys.REGISTRAR: r'registrar: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.iis.nu'
        self.update_reg_expressions(self._nu_expression)


class RegexPT(BaseParser):

    _pt_expression = {
        BaseKeys.DOMAIN_NAME: r'Domain: *(.+)',
        BaseKeys.CREATED: r'Creation Date: *(.+)',
        BaseKeys.EXPIRES: r'Expiration Date: *(.+)',
        BaseKeys.REGISTRANT_NAME: r'Owner Name: *(.+)',
        BaseKeys.REGISTRANT_ADDRESS: r'Owner Address: *(.+)',
        BaseKeys.REGISTRANT_CITY: r'Owner Locality: *(.+)',
        BaseKeys.REGISTRANT_ZIPCODE: r'Owner ZipCode: *(.+)',
        BaseKeys.NAME_SERVERS: r'Name Server: *(.+) \|',
        BaseKeys.STATUS: r'Domain Status: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.dns.pt'
        self.update_reg_expressions(self._pt_expression)


class RegexIN(BaseParser):

    _in_expression = {}

    def __init__(self):
        super().__init__()
        self.server = 'whois.registry.in'
        self.update_reg_expressions(self._in_expression)


class RegexCAT(BaseParser):

    _cat_expressions = {}

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.cat'
        self.update_reg_expressions(self._cat_expressions)


class RegexIE(BaseParser):

    _ie_expressions = {
        BaseKeys.REGISTRANT_NAME: r'Domain Holder: *(.+)',
        BaseKeys.CREATED: r'Registration Date: *(.+)',
        BaseKeys.EXPIRES: r'Renewal Date: *(.+)',
        BaseKeys.NAME_SERVERS: r'Nserver: *(.+)',
        BaseKeys.STATUS: r'Renewal status: *(.+)',
        BaseKeys.REGISTRAR: r'Account Name: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.iedr.ie'
        self.update_reg_expressions(self._ie_expressions)


class RegexNZ(BaseParser):

    _nz_expressions = {
        BaseKeys.REGISTRAR: r'registrar_name:\s*([^\n\r]+)',
        BaseKeys.UPDATED: r'domain_datelastmodified:\s*([^\n\r]+)',
        BaseKeys.CREATED: r'domain_dateregistered:\s*([^\n\r]+)',
        BaseKeys.EXPIRES: r'domain_datebilleduntil:\s*([^\n\r]+)',
        BaseKeys.NAME_SERVERS: r'ns_name_\d*:\s*([^\n\r]+)',
        BaseKeys.STATUS: r'status:\s*([^\n\r]+)',
        BaseKeys.REGISTRANT_NAME: r'registrant_contact_name:\s*([^\n\r]+)',
        BaseKeys.REGISTRANT_ADDRESS: r'registrant_contact_address\d*:\s*([^\n\r]+)',
        BaseKeys.REGISTRANT_CITY: r'registrant_contact_city:\s*([^\n\r]+)',
        BaseKeys.REGISTRANT_ZIPCODE: r'registrant_contact_postalcode:\s*([^\n\r]+)',
        BaseKeys.REGISTRANT_COUNTRY: r'registrant_contact_country:\s*([^\n\r]+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.srs.net.nz'
        self.update_reg_expressions(self._nz_expressions)


class RegexLU(BaseParser):

    _lu_expressions = {
        BaseKeys.CREATED: r'registered: *(.+)',
        BaseKeys.NAME_SERVERS: r'nserver: *(.+)',
        BaseKeys.STATUS: r'domaintype: *(.+)',
        BaseKeys.REGISTRAR: r'registrar-name: *(.+)',
        BaseKeys.REGISTRANT_ORGANIZATION: r'org-name: *(.+)',
        BaseKeys.REGISTRANT_ADDRESS: r'org-address: *(.+)',
        BaseKeys.REGISTRANT_ZIPCODE: r'org-zipcode:*(.+)',
        BaseKeys.REGISTRANT_CITY: r'org-city: *(.+)',
        BaseKeys.REGISTRANT_COUNTRY: r'org-country: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.dns.lu'
        self.update_reg_expressions(self._lu_expressions)


class RegexCZ(BaseParser):

    _cz_expressions = {
        BaseKeys.REGISTRANT_NAME: r'registrant: *(.+)',
        BaseKeys.REGISTRAR: r'registrar: *(.+)',
        BaseKeys.CREATED: r'registered: *(.+)',
        BaseKeys.UPDATED: r'changed: *(.+)',
        BaseKeys.EXPIRES: r'expire: *(.+)',
        BaseKeys.NAME_SERVERS: r'nserver: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.cz'
        self.update_reg_expressions(self._cz_expressions)


class RegexONLINE(BaseParser):

    _online_expressions = {
        BaseKeys.NAME_SERVERS: r'Name Server: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.online'
        self.update_reg_expressions(self._online_expressions)


class RegexHR(BaseParser):

    _hr_expressions = {
        BaseKeys.DOMAIN_NAME: 'Domain Name: *(.+)',
        BaseKeys.UPDATED: 'Updated Date: *(.+)',
        BaseKeys.CREATED: 'Creation Date: *(.+)',
        BaseKeys.EXPIRES: 'Registrar Registration Expiration Date: *(.+)',
        BaseKeys.NAME_SERVERS: 'Name Server: *(.+)',
        BaseKeys.REGISTRANT_NAME: 'Registrant Name:\s(.+)',
        BaseKeys.REGISTRANT_ADDRESS: 'Registrant Street:\s*(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.dns.hr'
        self.update_reg_expressions(self._hr_expressions)


class RegexHK(BaseParser):

    _hk_expressions = {
        BaseKeys.STATUS: r'Domain Status: *(.+)',
        BaseKeys.DNSSEC: r'DNSSEC: *(.+)',
        BaseKeys.REGISTRAR: r'Registrar Name: *(.+)',
        BaseKeys.REGISTRANT_NAME: r'Registrant Contact Information:\s*Company English Name.*:(.+)',
        BaseKeys.REGISTRANT_ADDRESS: r'(?<=Registrant Contact Information:)[\s\S]*?Address: (.*)',
        BaseKeys.REGISTRANT_COUNTRY: r'[Registrant Contact Information\w\W]+Country: ([\S\ ]+)',
        'registrant_email': r'[Registrant Contact Information\w\W]+Email: ([\S\ ]+)',
        BaseKeys.UPDATED: r'Updated Date: *(.+)',
        BaseKeys.CREATED: r'[Registrant Contact Information\w\W]+Domain Name Commencement Date: (.+)',
        BaseKeys.EXPIRES: r'[Registrant Contact Information\w\W]+Expiry Date: (.+)',
        BaseKeys.NAME_SERVERS: r'Name Servers Information:\s+((?:.+\n)*)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.hkirc.hk'
        self.update_reg_expressions(self._hk_expressions)


class RegexUA(BaseParser):

    _ua_expressions = {
        'domain_name': r'domain: *(.+)',
        BaseKeys.STATUS: r'status: *(.+)',
        BaseKeys.REGISTRAR: r'(?<=Registrar:)[\s\W\w]*?organization-loc:(.*)',
        BaseKeys.REGISTRANT_NAME: r'(?<=Registrant:)[\s\W\w]*?organization-loc:(.*)',
        BaseKeys.REGISTRANT_COUNTRY: r'(?<=Registrant:)[\s\W\w]*?country-loc:(.*)',
        BaseKeys.REGISTRANT_CITY: r'(?<=Registrant:)[\s\W\w]*?(?:address\-loc:\s+.*\n){2}address-loc:\s+(.*)\n',
        BaseKeys.REGISTRANT_STATE: r'(?<=Registrant:)[\s\W\w]*?(?:address\-loc:\s+.*\n){1}address-loc:\s+(.*)\n',
        BaseKeys.REGISTRANT_ADDRESS: r'(?<=Registrant:)[\s\W\w]*?address-loc:\s+(.*)\n',
        BaseKeys.REGISTRANT_ZIPCODE: r'(?<=Registrant:)[\s\W\w]*?postal-code-loc:(.*)',
        BaseKeys.UPDATED: 'modified: *(.+)',
        BaseKeys.CREATED: 'created: (.+)',
        BaseKeys.EXPIRES: 'expires: (.+)',
        BaseKeys.NAME_SERVERS: 'nserver: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.ua'
        self.update_reg_expressions(self._ua_expressions)


class RegexHN(BaseParser):

    _hn_expressions = {
        BaseKeys.STATUS:                   r'Domain Status: *(.+)',
        BaseKeys.REGISTRAR:                r'Registrar: *(.+)',
        BaseKeys.REGISTRANT_NAME:          r'Registrant Name: (.+)',
        BaseKeys.REGISTRANT_ORGANIZATION:  r'Registrant Organization: (.+)',
        BaseKeys.REGISTRANT_CITY:          r'Registrant City: (.*)',
        BaseKeys.REGISTRANT_ADDRESS:       r'Registrant Street: (.*)',
        BaseKeys.REGISTRANT_STATE:         r'Registrant State/Province: (.*)',
        BaseKeys.REGISTRANT_ZIPCODE:       r'Registrant Postal Code: (.*)',
        BaseKeys.REGISTRANT_COUNTRY:       r'Registrant Country: (.+)',
        BaseKeys.UPDATED:                  r'Updated Date: *(.+)',
        BaseKeys.CREATED:                  r'Creation Date: *(.+)',
        BaseKeys.EXPIRES:                  r'Registry Expiry Date: *(.+)',
        BaseKeys.NAME_SERVERS:             r'Name Server: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.hn'
        self.update_reg_expressions(self._hn_expressions)


class RegexLAT(BaseParser):

    _lat_expressions = {
        BaseKeys.STATUS: r'Domain Status: *(.+)',
        BaseKeys.REGISTRAR: r'Registrar: *(.+)',
        BaseKeys.REGISTRANT_NAME: r'Registrant Name: (.+)',
        BaseKeys.REGISTRANT_ORGANIZATION: r'Registrant Organization: (.+)',
        BaseKeys.REGISTRANT_CITY: r'Registrant City: (.*)',
        BaseKeys.REGISTRANT_ADDRESS: r'Registrant Street: (.*)',
        BaseKeys.REGISTRANT_STATE: r'Registrant State/Province: (.*)',
        BaseKeys.REGISTRANT_ZIPCODE: r'Registrant Postal Code: (.*)',
        BaseKeys.REGISTRANT_COUNTRY: r'Registrant Country: (.+)',
        BaseKeys.UPDATED: r'Updated Date: *(.+)',
        BaseKeys.CREATED: r'Creation Date: *(.+)',
        BaseKeys.EXPIRES: r'Registry Expiry Date: *(.+)',
        BaseKeys.NAME_SERVERS: r'Name Server: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.lat'
        self.update_reg_expressions(self._lat_expressions)


class RegexCN(BaseParser):

    _cn_expressions = {
        BaseKeys.REGISTRAR: r'Sponsoring Registrar: *(.+)',
        BaseKeys.CREATED: r'Registration Time: *(.+)',
        BaseKeys.EXPIRES: r'Expiration Time: *(.+)',
        BaseKeys.NAME_SERVERS: r'Name Server: *(.+)',
        BaseKeys.STATUS: r'Domain Status: *(.+)',
        BaseKeys.DNSSEC: r'DNSSEC: *([\S]+)',
        BaseKeys.REGISTRANT_NAME: r'Registrant: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.cnnic.cn'
        self.update_reg_expressions(self._cn_expressions)


class RegexAPP(BaseParser):

    _app_expressions = {
        BaseKeys.REGISTRAR: r'Registrar: *(.+)',
        BaseKeys.UPDATED: r'Updated Date: *(.+)',
        BaseKeys.CREATED: r'Creation Date: *(.+)',
        BaseKeys.EXPIRES: r'Expir\w+ Date: *(.+)',
        BaseKeys.NAME_SERVERS: r'Name Server: *(.+)',
        BaseKeys.STATUS: r'Status: *(.+)',
        BaseKeys.DNSSEC: r'dnssec: *([\S]+)',
        BaseKeys.REGISTRANT_NAME: r'Registrant Name: *(.+)',
        BaseKeys.REGISTRANT_ORGANIZATION: r'Registrant\s*Organization: *(.+)',
        BaseKeys.REGISTRANT_ADDRESS: r'Registrant Street: *(.+)',
        BaseKeys.REGISTRANT_CITY: r'Registrant City: *(.+)',
        BaseKeys.REGISTRANT_STATE: r'Registrant State/Province: *(.+)',
        BaseKeys.REGISTRANT_ZIPCODE: r'Registrant Postal Code: *(.+)',
        BaseKeys.REGISTRANT_COUNTRY: r'Registrant Country: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.google'
        self.update_reg_expressions(self._app_expressions)


class RegexMONEY(BaseParser):

    _money_expressions = {
        BaseKeys.DOMAIN_NAME: r'Domain Name: *(.+)',
        BaseKeys.REGISTRAR: r'Registrar: *(.+)',
        BaseKeys.UPDATED: r'Updated Date: *(.+)',
        BaseKeys.CREATED: r'Creation Date: *(.+)',
        BaseKeys.EXPIRES: r'Registry Expiry Date: *(.+)',
        BaseKeys.NAME_SERVERS: r'Name Server: *(.+)',
        BaseKeys.STATUS: r'Domain Status: *(.+)',
        BaseKeys.DNSSEC: r'DNSSEC: *(.+)',
        BaseKeys.REGISTRANT_NAME: r'Registrant Name: *(.+)',
        BaseKeys.REGISTRANT_ORGANIZATION: r'Registrant Organization: *(.+)',
        BaseKeys.REGISTRANT_ADDRESS: r'Registrant Street: *(.+)',
        BaseKeys.REGISTRANT_CITY: r'Registrant City: *(.+)',
        BaseKeys.REGISTRANT_STATE: r'Registrant State/Province: *(.+)',
        BaseKeys.REGISTRANT_ZIPCODE: r'Registrant Postal Code: *(.+)',
        BaseKeys.REGISTRANT_COUNTRY: r'Registrant Country: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.money'
        self.update_reg_expressions(self._money_expressions)


class RegexAR(BaseParser):

    _ar_expressions = {
        BaseKeys.DOMAIN_NAME: r'domain: *(.+)',
        BaseKeys.REGISTRAR: r'registrar: *(.+)',
        BaseKeys.UPDATED: r'changed: *(.+)',
        BaseKeys.CREATED: r'created: *(.+)',
        BaseKeys.EXPIRES: r'expire: *(.+)',
        BaseKeys.NAME_SERVERS: r'nserver: *(.+) \(.*\)',
        BaseKeys.STATUS: r'Domain Status: *(.+)',
        BaseKeys.REGISTRANT_NAME: r'name: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.ar'
        self.update_reg_expressions(self._ar_expressions)


class RegexBY(BaseParser):

    _by_expressions = {
        BaseKeys.DOMAIN_NAME: r'Domain Name: *(.+)',
        BaseKeys.REGISTRAR: r'Registrar: *(.+)',
        BaseKeys.UPDATED: r'Updated Date: *(.+)',
        BaseKeys.CREATED: r'Creation Date: *(.+)',
        BaseKeys.EXPIRES: r'Expiration Date: *(.+)',
        BaseKeys.NAME_SERVERS: r'Name Server: *(.+)',
        BaseKeys.STATUS: r'Domain Status: *(.+)',
        BaseKeys.REGISTRANT_NAME: r'Person: *(.+)',
        BaseKeys.REGISTRANT_ORGANIZATION: r'Org: *(.+)',
        BaseKeys.REGISTRANT_COUNTRY: r'Country: *(.+)',
        BaseKeys.REGISTRANT_ADDRESS: r'Address: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.cctld.by'
        self.update_reg_expressions(self._by_expressions)


class RegexCR(BaseParser):

    _cr_expressions = {
        BaseKeys.DOMAIN_NAME: r'domain: *(.+)',
        BaseKeys.REGISTRANT_NAME: r'registrant: *(.+)',
        BaseKeys.REGISTRAR: r'registrar: *(.+)',
        BaseKeys.UPDATED: r'changed: *(.+)',
        BaseKeys.CREATED: r'registered: *(.+)',
        BaseKeys.EXPIRES: r'expire: *(.+)',
        BaseKeys.NAME_SERVERS: r'nserver: *(.+)',
        BaseKeys.STATUS: r'status: *(.+)',
        BaseKeys.REGISTRANT_ORGANIZATION: r'org: *(.+)',
        BaseKeys.REGISTRANT_ADDRESS: r'address: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.cr'
        self.update_reg_expressions(self._cr_expressions)


class RegexVE(BaseParser):

    _ve_expressions = {
        BaseKeys.DOMAIN_NAME: r'domain: *(.+)',
        BaseKeys.CREATED: 'registered: *(.+)',
        BaseKeys.EXPIRES: 'expire: *(.+)',
        BaseKeys.UPDATED: 'changed: *(.+)',
        BaseKeys.REGISTRAR: r'registrar: *(.+)',
        BaseKeys.NAME_SERVERS: r'nserver: *(.+)',
        BaseKeys.REGISTRANT_NAME: r'registrant: *(.+)',
        BaseKeys.REGISTRANT_ADDRESS: r'address: *(.+)',
        BaseKeys.REGISTRANT_CITY: r'address:.+\naddress: *(.+)',
        BaseKeys.REGISTRANT_ZIPCODE: r'(?:address:.+\n){2}address: *(.+)',
        BaseKeys.REGISTRANT_STATE: r'(?:address:.+\n){3}address: *(.+)',
        BaseKeys.REGISTRANT_COUNTRY: r'(?:address:.+\n){4}address: *(.+)',
        BaseKeys.REGISTRANT_ORGANIZATION: r'org: *(.+)',
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
        BaseKeys.STATUS: r'Status: *(.+)',
        BaseKeys.REGISTRANT_NAME: r'Registrant Contact Name: *(.+)',
        BaseKeys.REGISTRANT_ORGANIZATION: r'Registrant Contact Organisation: *(.+)',
        BaseKeys.REGISTRAR: r'Registrar Name: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.aeda.net.ae'
        self.update_reg_expressions(self._ae_expressions)


class RegexSI(BaseParser):

    _si_expressions = {
        BaseKeys.REGISTRAR: r'registrar: *(.+)',
        BaseKeys.NAME_SERVERS: r'nameserver: *(.+)',
        BaseKeys.REGISTRANT_NAME: r'registrant: *(.+)',
        BaseKeys.CREATED: r'created: *(.+)',
        BaseKeys.EXPIRES: r'expire: *(.+)',
        BaseKeys.DOMAIN_NAME: 'domain: *(.+)',
        BaseKeys.STATUS: 'status: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.register.si'
        self.update_reg_expressions(self._si_expressions)


class RegexNO(BaseParser):
    """
    % The whois service at port 43 is intended to contribute to resolving
    % technical problems where individual domains threaten the
    % functionality, security and stability of other domains or the
    % internet as an infrastructure. It does not give any information
    % about who the holder of a domain is. To find information about a
    % domain holder, please visit our website:
    % https://www.norid.no/en/domeneoppslag/
    """

    _no_expressions = {
        BaseKeys.CREATED        : r'Created:\s*(.+)',
        BaseKeys.UPDATED        : r'Last updated:\s*(.+)',
        BaseKeys.NAME_SERVERS   : r'Name Server Handle\.*: *(.+)',
        BaseKeys.REGISTRAR      : r'Registrar Handle\.*: *(.+)',
        BaseKeys.DOMAIN_NAME    : r'Domain Name\.*: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.norid.no'
        self.update_reg_expressions(self._no_expressions)


class RegexKZ(BaseParser):

    _kz_expressions = {
        BaseKeys.REGISTRAR                  : r'Current Registar:\s*(.+)',  # "Registar" typo exists on the whois server
        BaseKeys.CREATED                    : r'Domain created:\s*(.+)\s\(',
        BaseKeys.UPDATED                    : r'Last modified\s:\s*(.+)\s\(',
        BaseKeys.NAME_SERVERS               : r'.+\sserver\.*:\s*(.+)',
        BaseKeys.STATUS                     : r'Domain status\s:\s(.+)',
        BaseKeys.REGISTRANT_ORGANIZATION    : r'Organization Using Domain Name\nName\.*:\s(.+)',
        BaseKeys.REGISTRANT_ADDRESS         : r'Street Address\.*:\s*(.+)',
        BaseKeys.REGISTRANT_CITY            : r'City\.*:\s*(.+)',
        BaseKeys.REGISTRANT_ZIPCODE         : r'Postal Code\.*:\s*(.+)',
        BaseKeys.REGISTRANT_COUNTRY         : r'Country\.*:\s*(.+)',
        BaseKeys.REGISTRANT_NAME            : r'Organization Name\.*:\s*(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.kz'
        self.update_reg_expressions(self._kz_expressions)


class RegexTOP(BaseParser):

    _top_expressions = {}

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.top'
        self.update_reg_expressions(self._top_expressions)


class RegexIR(BaseParser):

    _ir_expressions = {
        BaseKeys.UPDATED                    : r'last-updated: *(.+)',
        BaseKeys.EXPIRES                    : r'expire-date: *(.+)',
        BaseKeys.REGISTRANT_ORGANIZATION    : r'org: *(.+)',
        BaseKeys.REGISTRANT_NAME            : r'remarks:\s+\(Domain Holder\) *(.+)',
        BaseKeys.REGISTRANT_ADDRESS         : r'remarks:\s+\(Domain Holder Address\) *(.+)',
        BaseKeys.NAME_SERVERS               : r'nserver: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.ir'
        self.update_reg_expressions(self._ir_expressions)

    def parse(self, blob: str) -> Dict[str, Any]:
        """
        Custom address parsing required.
        """
        parsed_output = {}
        for key, regex in self.reg_expressions.items():
            if key == BaseKeys.REGISTRANT_ADDRESS:
                match = self.find_match(regex, blob)
                # need to break up from address field
                address, city, state, country = match.split(', ')
                parsed_output[BaseKeys.REGISTRANT_ADDRESS] = address
                parsed_output[BaseKeys.REGISTRANT_CITY] = city
                parsed_output[BaseKeys.REGISTRANT_STATE] = state
                parsed_output[BaseKeys.REGISTRANT_COUNTRY] = country
            elif not parsed_output.get(key):
                parsed_output[key] = self.find_match(regex, blob, many=key in self.multiple_match_keys)

            # convert dates
            if key in self.date_keys and parsed_output.get(key, None):
                parsed_output[key] = self._parse_date(parsed_output.get(key))

        return parsed_output


class RegexXYZ(BaseParser):

    _xyz_expressions = {}

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.xyz'
        self.update_reg_expressions(self._xyz_expressions)


class RegexICU(BaseParser):

    _icu_expressions = {}

    def __init__(self):
        super().__init__()
        self.server = 'whois.nic.icu'
        self.update_reg_expressions(self._icu_expressions)


class RegexTK(BaseParser):

    _tk_expressions = {
        BaseKeys.DOMAIN_NAME    : r'Domain registered: *(.+)',
        BaseKeys.EXPIRES        : r'Record will expire on: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.dot.tk'
        self.update_reg_expressions(self._tk_expressions)


class RegexCC(BaseParser):

    _cc_expressions = {
        BaseKeys.STATUS: r'Domain Status: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.server = 'ccwhois.verisign-grs.com'
        self.update_reg_expressions(self._cc_expressions)


class RegexEDU(BaseParser):

    _edu_expressions = {
        BaseKeys.CREATED                    : 'Domain record activated: *(.+)',
        BaseKeys.UPDATED                    : 'Domain record last updated: *(.+)',
        BaseKeys.EXPIRES                    : 'Domain expires: *(.+)',
        BaseKeys.REGISTRANT_NAME            : r'Registrant:(.*?)Admin',
        BaseKeys.NAME_SERVERS               : r'Name Servers:(.*?)Domain'
    }

    def __init__(self):
        super().__init__()
        self.server = 'whois.educause.edu'
        self.update_reg_expressions(self._edu_expressions)

    def parse(self, blob: str) -> Dict[str, Any]:
        parsed_output = {}
        processed_registrant = False
        for key, regex in self.reg_expressions.items():
            if key.startswith('registrant'):
                if not processed_registrant:
                    # process all registrant information here
                    match = self.find_match(regex, blob, flags=re.DOTALL|re.IGNORECASE, many=False)
                    registrant_info_list = match.split('\n\t')
                    # registrant name is always first in split output
                    parsed_output[BaseKeys.REGISTRANT_NAME] = registrant_info_list[0]
                    # country is always last line
                    parsed_output[BaseKeys.REGISTRANT_COUNTRY] = registrant_info_list[-1]
                    # registrant address is always third-to-last line
                    parsed_output[BaseKeys.REGISTRANT_ADDRESS] = registrant_info_list[-3]
                    # break up city, state, and zipcode information; always second-to-last line
                    city, state_zipcode = registrant_info_list[-2].split(',')
                    state, zipcode = state_zipcode.lstrip().split()
                    parsed_output[BaseKeys.REGISTRANT_CITY] = city
                    parsed_output[BaseKeys.REGISTRANT_STATE] = state
                    parsed_output[BaseKeys.REGISTRANT_ZIPCODE] = zipcode
                    # sometimes registrant organization exists as 2nd item
                    if len(registrant_info_list) > 4:
                        parsed_output[BaseKeys.REGISTRANT_ORGANIZATION] = registrant_info_list[1]
                    processed_registrant = True

            elif key == BaseKeys.NAME_SERVERS:
                match = self.find_match(regex, blob, flags=re.DOTALL|re.IGNORECASE, many=False)
                parsed_output[BaseKeys.NAME_SERVERS] = match.split('\n\t')

            else:
                parsed_output[key] = self.find_match(regex, blob)

            # convert dates
            if key in self.date_keys and parsed_output.get(key, None):
                parsed_output[key] = self._parse_date(parsed_output.get(key))

        return parsed_output
