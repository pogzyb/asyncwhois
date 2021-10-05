import datetime
import re
from enum import Enum
from typing import Dict, Any, Union, List

from .errors import NotFoundError

# Date formats from richardpenman/pywhois
KNOWN_DATE_FORMATS = [
    '%d-%b-%Y',  # 02-jan-2000
    '%d-%B-%Y',  # 11-February-2000
    '%d-%m-%Y',  # 20-10-2000
    '%Y-%m-%d',  # 2000-01-02
    '%d.%m.%Y',  # 2.1.2000
    '%Y.%m.%d',  # 2000.01.02
    '%Y/%m/%d',  # 2000/01/02
    '%Y%m%d',  # 20170209
    '%d/%m/%Y',  # 02/01/2013
    '%Y. %m. %d.',  # 2000. 01. 02.
    '%Y.%m.%d %H:%M:%S',  # 2014.03.08 10:28:24
    '%d-%b-%Y %H:%M:%S %Z',  # 24-Jul-2009 13:20:03 UTC
    '%a %b %d %H:%M:%S %Z %Y',  # Tue Jun 21 23:59:59 GMT 2011
    '%Y-%m-%dT%H:%M:%SZ',  # 2007-01-26T19:10:31Z
    '%Y-%m-%dT%H:%M:%S.%fZ',  # 2018-12-01T16:17:30.568Z
    '%Y-%m-%dT%H:%M:%S%z',  # 2013-12-06T08:17:22-0800
    '%Y-%m-%d %H:%M:%SZ',  # 2000-08-22 18:55:20Z
    '%Y-%m-%d %H:%M:%S',  # 2000-08-22 18:55:20
    '%d %b %Y %H:%M:%S',  # 08 Apr 2013 05:44:00
    '%d/%m/%Y %H:%M:%S',  # 23/04/2015 12:00:07 EEST
    '%d/%m/%Y %H:%M:%S %Z',  # 23/04/2015 12:00:07 EEST
    '%d/%m/%Y %H:%M:%S.%f %Z',  # 23/04/2015 12:00:07.619546 EEST
    '%Y-%m-%d %H:%M:%S.%f',  # 23/04/2015 12:00:07.619546
    '%B %d %Y',  # August 14 2017
    '%d.%m.%Y %H:%M:%S',  # 08.03.2014 10:28:24
    '%a %b %d %Y',  # Tue Dec 12 2000
]


class BaseKeys(str, Enum):
    DOMAIN_NAME = 'domain_name'

    CREATED = 'created'
    UPDATED = 'updated'
    EXPIRES = 'expires'

    REGISTRAR = 'registrar'

    REGISTRANT_NAME = 'registrant_name'
    REGISTRANT_ORGANIZATION = 'registrant_organization'
    REGISTRANT_ADDRESS = 'registrant_address'
    REGISTRANT_CITY = 'registrant_city'
    REGISTRANT_STATE = 'registrant_state'
    REGISTRANT_COUNTRY = 'registrant_country'
    REGISTRANT_ZIPCODE = 'registrant_zipcode'
    REGISTRANT_PHONE = 'registrant_phone'
    REGISTRANT_FAX = 'registrant_fax'
    REGISTRANT_EMAIL = 'registrant_email'

    ADMIN_NAME = 'admin_name'
    ADMIN_ID = 'admin_id'
    ADMIN_ORGANIZATION = 'admin_organization'
    ADMIN_ADDRESS = 'admin_address'
    ADMIN_CITY = 'admin_city'
    ADMIN_STATE = 'admin_state'
    ADMIN_COUNTRY = 'admin_country'
    ADMIN_ZIPCODE = 'admin_zipcode'
    ADMIN_PHONE = 'admin_phone'
    ADMIN_FAX = 'admin_fax'
    ADMIN_EMAIL = 'admin_email'

    BILLING_NAME = 'billing_name'
    BILLING_ID = 'billing_id'
    BILLING_ORGANIZATION = 'billing_organization'
    BILLING_ADDRESS = 'billing_address'
    BILLING_CITY = 'billing_city'
    BILLING_STATE = 'billing_state'
    BILLING_COUNTRY = 'billing_country'
    BILLING_ZIPCODE = 'billing_zipcode'
    BILLING_PHONE = 'billing_phone'
    BILLING_FAX = 'billing_fax'
    BILLING_EMAIL = 'billing_email'

    TECH_NAME = 'tech_name'
    TECH_ID = 'tech_id'
    TECH_ORGANIZATION = 'tech_organization'
    TECH_ADDRESS = 'tech_address'
    TECH_CITY = 'tech_city'
    TECH_STATE = 'tech_state'
    TECH_COUNTRY = 'tech_country'
    TECH_ZIPCODE = 'tech_zipcode'
    TECH_PHONE = 'tech_phone'
    TECH_FAX = 'tech_fax'
    TECH_EMAIL = 'tech_email'

    DNSSEC = 'dnssec'
    STATUS = 'status'
    NAME_SERVERS = 'name_servers'

    def __repr__(self):
        return self.value

    def __str__(self):
        return self.value


class BaseParser:
    base_expressions = {
        BaseKeys.DOMAIN_NAME: r'Domain Name: *(.+)',

        BaseKeys.CREATED: r'Creation Date: *(.+)',
        BaseKeys.UPDATED: r'Updated Date: *(.+)',
        BaseKeys.EXPIRES: r'Expir\w+\sDate: *(.+)',

        BaseKeys.REGISTRAR: r'Registrar: *(.+)',

        BaseKeys.REGISTRANT_NAME: r'Registrant Name: *(.+)',
        BaseKeys.REGISTRANT_ORGANIZATION: r'Registrant Organization: *(.+)',
        BaseKeys.REGISTRANT_ADDRESS: r'Registrant Street: *(.+)',
        BaseKeys.REGISTRANT_CITY: r'Registrant City: *(.+)',
        BaseKeys.REGISTRANT_STATE: r'Registrant State/Province: *(.+)',
        BaseKeys.REGISTRANT_ZIPCODE: r'Registrant Postal Code: *(.+)',
        BaseKeys.REGISTRANT_COUNTRY: r'Registrant Country: *(.+)',
        BaseKeys.REGISTRANT_EMAIL: r'Registrant Email: *(.+)',

        BaseKeys.DNSSEC: r'DNSSEC: *([\S]+)',
        BaseKeys.STATUS: r'Status: *(.+)',
        BaseKeys.NAME_SERVERS: r'Name server: *(.+)',

        BaseKeys.ADMIN_NAME: r'Admin Name: (.+)',
        BaseKeys.ADMIN_ID: r'Admin ID: (.+)',
        BaseKeys.ADMIN_ORGANIZATION: r'Admin Organization: (.+)',
        BaseKeys.ADMIN_CITY: r'Admin City: (.*)',
        BaseKeys.ADMIN_ADDRESS: r'Admin Street: (.*)',
        BaseKeys.ADMIN_STATE: r'Admin State/Province: (.*)',
        BaseKeys.ADMIN_ZIPCODE: r'Admin Postal Code: (.*)',
        BaseKeys.ADMIN_COUNTRY: r'Admin Country: (.+)',
        BaseKeys.ADMIN_PHONE: r'Admin Phone: (.+)',
        BaseKeys.ADMIN_FAX: r'Admin Fax: (.+)',
        BaseKeys.ADMIN_EMAIL: r'Admin Email: (.+)',

        BaseKeys.BILLING_NAME: r'Billing Name: (.+)',
        BaseKeys.BILLING_ID: r'Billing ID: (.+)',
        BaseKeys.BILLING_ORGANIZATION: r'Billing Organization: (.+)',
        BaseKeys.BILLING_CITY: r'Billing City: (.*)',
        BaseKeys.BILLING_ADDRESS: r'Billing Street: (.*)',
        BaseKeys.BILLING_STATE: r'Billing State/Province: (.*)',
        BaseKeys.BILLING_ZIPCODE: r'Billing Postal Code: (.*)',
        BaseKeys.BILLING_COUNTRY: r'Billing Country: (.+)',
        BaseKeys.BILLING_PHONE: r'Billing Phone: (.+)',
        BaseKeys.BILLING_FAX: r'Billing Fax: (.+)',
        BaseKeys.BILLING_EMAIL: r'Billing Email: (.+)',

        BaseKeys.TECH_NAME: r'Tech Name: (.+)',
        BaseKeys.TECH_ID: r'Tech ID: (.+)',
        BaseKeys.TECH_ORGANIZATION: r'Tech Organization: (.+)',
        BaseKeys.TECH_CITY: r'Tech City: (.*)',
        BaseKeys.TECH_ADDRESS: r'Tech Street: (.*)',
        BaseKeys.TECH_STATE: r'Tech State/Province: (.*)',
        BaseKeys.TECH_ZIPCODE: r'Tech Postal Code: (.*)',
        BaseKeys.TECH_COUNTRY: r'Tech Country: (.+)',
        BaseKeys.TECH_PHONE: r'Tech Phone: (.+)',
        BaseKeys.TECH_FAX: r'Tech Fax: (.+)',
        BaseKeys.TECH_EMAIL: r'Tech Email: (.+)',
    }

    multiple_match_keys = (BaseKeys.NAME_SERVERS, BaseKeys.STATUS)
    date_keys = (BaseKeys.CREATED, BaseKeys.UPDATED, BaseKeys.EXPIRES)

    def __init__(self):
        self.reg_expressions = self.base_expressions.copy()

    def update_reg_expressions(self, expressions_update: Dict[str, Any]) -> None:
        """
        Updates the `reg_expressions` dictionary
        :param expressions_update: dictionary of keys/regexes to update
        """
        self.reg_expressions.update(expressions_update)

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

    def find_multiline_match(self, start: str, blob: str) -> List[str]:
        """
        Used to find multiple lines related to a single key within the
        WHOIS query response. Assumes the values are on a newline below
        the key, and that a blank line separates the last value from the
        next key or end of the text.

        Example:
        -------
        example_blob = '''
            Name servers:
                 ns1.google.com
                 ns2.google.com
                 ns3.google.com
                 ns4.google.com

        '''
        find_multiline_match('Name servers:\n', example_blob)
        # would return... ['ns1.google.com', 'ns2.google.com', 'ns3.google.com', 'ns4.google.com']

        :param start: a key that identifies where to begin the multiline search in blob
        :param blob: the whois query text
        :return: a list of values as strings
        """
        matches = []
        regex_string = start + r'\s+([A-Za-z0-9\.\s]+\n\n)'
        multiline_match = re.search(regex_string, blob, re.DOTALL | re.IGNORECASE)
        if multiline_match:
            matches = self._process_many(multiline_match.group(1))
        return matches

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
            matches = [self._process(m) for m in match if m]
            return [m for m in matches if m]  # remove empty strings
        else:
            match = self._process(match)
            return [match] if match else []  # remove empty strings

    @staticmethod
    def _process(match: str) -> str:
        if match:
            return match.rstrip('\r').rstrip('\n').lstrip('\t').lstrip().rstrip()


class WhoIsParser:
    _no_match_checks = [
        'no match',
        'not found',
        'no entries found',
        'invalid query',
        'domain name not known',
        'no object found'
    ]

    def __init__(self, tld: str):
        self.parser_output = {}
        self._parser = self._init_parser(tld)

    def parse(self, blob: str) -> None:
        """
        Parses `blob` (whois query output) using a parser class.
        Saves the results into the `parser_output` attribute.
        """
        if any([n in blob.lower() for n in self._no_match_checks]):
            raise NotFoundError(f'Domain not found!')
        self.parser_output = self._parser.parse(blob)

    @staticmethod
    def _init_parser(tld: str) -> BaseParser:
        """
        Retrieves the parser instance which can most accurately extract
        key/value pairs from the whois server output for the given `tld`.
        :param tld: the top level domain
        :return: instance of BaseParser or a BaseParser sub-class
        """

        # the cases specified below do not follow a common format,
        # and so, must be parsed with custom defined regex sub classes.
        if tld == 'ae':
            return RegexAE()
        elif tld == 'ar':
            return RegexAR()
        elif tld == 'at':
            return RegexAT()
        elif tld == 'au':
            return RegexAU()
        elif tld == 'aw':
            return RegexAW()
        elif tld == 'ax':
            return RegexAX()
        elif tld == 'be':
            return RegexBE()
        elif tld == 'br':
            return RegexBR()
        elif tld == 'by':
            return RegexBY()
        elif tld == 'cc':
            return RegexCC()
        elif tld == 'ch':
            return RegexCH()
        elif tld == 'cl':
            return RegexCL()
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
        elif tld == 'ge':
            return RegexGE()
        elif tld == 'gg':
            return RegexGG()
        elif tld == 'gq':
            return RegexGQ()
        elif tld == 'hk':
            return RegexHK()
        elif tld == 'hr':
            return RegexHR()
        elif tld == 'id':
            return RegexID()
        elif tld == 'ie':
            return RegexIE()
        elif tld == 'il':
            return RegexIL()
        elif tld == 'ir':
            return RegexIR()
        elif tld == 'is':
            return RegexIS()
        elif tld == 'it':
            return RegexIT()
        elif tld == 'jp':
            return RegexJP()
        elif tld == 'kg':
            return RegexKG()
        elif tld == 'kr':
            return RegexKR()
        elif tld == 'kz':
            return RegexKZ()
        elif tld == 'li':
            return RegexLI()
        elif tld == 'lu':
            return RegexLU()
        elif tld == 'lv':
            return RegexLV()
        elif tld == 'ma':
            return RegexMA()
        elif tld == 'mx':
            return RegexMX()
        elif tld == 'nl':
            return RegexNL()
        elif tld == 'no':
            return RegexNO()
        elif tld == 'nu':
            return RegexNU()
        elif tld == 'nz':
            return RegexNZ()
        elif tld == 'pe':
            return RegexPE()
        elif tld == 'pl':
            return RegexPL()
        elif tld == 'pt':
            return RegexPT()
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
        elif tld == 'su':
            return RegexSU()
        elif tld == 'tk':
            return RegexTK()
        elif tld == 'tr':
            return RegexTR()
        elif tld == 'tw':
            return RegexTW()
        elif tld == 'ua':
            return RegexUA()
        elif tld == 'uk':
            return RegexUK()
        elif tld == 've':
            return RegexVE()
        else:
            # The BaseParser can handle all "Generic" and some "Country-Code" TLDs.
            # If the parsed output of lookup is not what you expect or even incorrect,
            # check for and then modify the existing Regex subclass or create a new one.
            return BaseParser()


# ==============================
# Custom Query Output Parsers
# ==============================

class RegexRU(BaseParser):
    _ru_expressions = {
        BaseKeys.DOMAIN_NAME: r'domain: *(.+)',
        BaseKeys.CREATED: r'created: *(.+)',
        BaseKeys.EXPIRES: r'paid-till: *(.+)',
        BaseKeys.REGISTRANT_ORGANIZATION: r'org: *(.+)',
        BaseKeys.STATUS: r'state: *(.+)',
        BaseKeys.NAME_SERVERS: r'nserver: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._ru_expressions)


class RegexCL(BaseParser):
    _cl_expressions = {
        BaseKeys.NAME_SERVERS: r'Name server: *(.+)',
        BaseKeys.REGISTRANT_NAME: r'Registrant name: *(.+)',
        BaseKeys.REGISTRANT_ORGANIZATION: r'Registrant organisation: *(.+)',
        BaseKeys.REGISTRAR: r'Registrar name: *(.+)',
        BaseKeys.EXPIRES: r'Expiration date: (\d{4}-\d{2}-\d{2})',
        BaseKeys.CREATED: r'Creation date: (\d{4}-\d{2}-\d{2})',
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._cl_expressions)


class RegexPL(BaseParser):
    _pl_expressions = {
        BaseKeys.DOMAIN_NAME: r'DOMAIN NAME: *(.+)\n',
        BaseKeys.REGISTRAR: r'REGISTRAR:\s*(.+)',
        BaseKeys.CREATED: r'created: *(.+)',
        BaseKeys.EXPIRES: r'option expiration date: *(.+)',
        BaseKeys.UPDATED: r'last modified: *(.+)\n',
        BaseKeys.DNSSEC: r'dnssec: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._pl_expressions)

    def parse(self, blob: str) -> Dict[str, Any]:
        parsed_output = super().parse(blob)
        nameservers_match = self.find_match(r'nameservers:*(.+)\ncreated:\s', blob, flags=re.DOTALL | re.IGNORECASE)
        if nameservers_match:
            parsed_output[BaseKeys.NAME_SERVERS] = [self._process(m) for m in nameservers_match.split('\n')]
        return parsed_output


class RegexRO(BaseParser):
    # % The ROTLD WHOIS service on port 43 never discloses any information concerning the registrant.

    _ro_expressions = {
        BaseKeys.CREATED: r'Registered On: *(.+)',
        BaseKeys.EXPIRES: r'Expires On: *(.+)',
        BaseKeys.NAME_SERVERS: r'Nameserver: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._ro_expressions)


class RegexPE(BaseParser):
    _pe_expressions = {
        BaseKeys.REGISTRANT_NAME: r'Registrant name: *(.+)',
        BaseKeys.REGISTRAR: r'Sponsoring Registrar: *(.+)',
        BaseKeys.DNSSEC: r'DNSSEC: *(.+)',
        BaseKeys.NAME_SERVERS: r'Name server: *(.+)',
        BaseKeys.STATUS: r'Domain Status: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._pe_expressions)


class RegexEE(BaseParser):
    _ee_expressions = {
        BaseKeys.DOMAIN_NAME: r'Domain: *[\n\r]+\s*name: *([^\n\r]+)',
        BaseKeys.STATUS: r'status: *([^\n\r]+)',
        BaseKeys.CREATED: r'registered: *([^\n\r]+)',
        BaseKeys.UPDATED: r'changed: *([^\n\r]+)',
        BaseKeys.EXPIRES: r'expire: *([^\n\r]+)',
        BaseKeys.REGISTRAR: r'Registrar: *[\n\r]+\s*name: *([^\n\r]+)',
        BaseKeys.NAME_SERVERS: r'nserver: *(.*)',
        BaseKeys.REGISTRANT_COUNTRY: r'country: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._ee_expressions)


class RegexFR(BaseParser):
    _fr_expressions = {
        BaseKeys.CREATED: r'created: (\d{4}-\d{2}-\d{2})',
        BaseKeys.UPDATED: r'last-update: (\d{4}-\d{2}-\d{2})',
        BaseKeys.EXPIRES: r'Expiry Date: (\d{4}-\d{2}-\d{2})',
        BaseKeys.NAME_SERVERS: r'nserver: *(.+)'
    }

    def __init__(self):
        super().__init__()
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
        self.update_reg_expressions(self._br_expressions)


class RegexKR(BaseParser):
    _kr_expressions = {
        BaseKeys.CREATED: r'Registered Date *: (\d{4}\.\s\d{2}\.\s\d{2}\.)',
        BaseKeys.UPDATED: r'Last Updated Date *: (\d{4}\.\s\d{2}\.\s\d{2}\.)',
        BaseKeys.EXPIRES: r'Expiration Date *: (\d{4}\.\s\d{2}\.\s\d{2}\.)',
        BaseKeys.REGISTRANT_NAME: r'Registrant *: (.+)',
        BaseKeys.DNSSEC: r'DNSSEC *: ([a-zA-Z]+)',
        BaseKeys.REGISTRANT_ZIPCODE: r'Registrant Zip Code: *: (.+)',
        BaseKeys.REGISTRANT_ADDRESS: r'Registrant Address *: (.+)',
        BaseKeys.DOMAIN_NAME: r'Domain *: (.+)',
        BaseKeys.NAME_SERVERS: r'Host Name *: (.+)'
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._kr_expressions)


class RegexEU(BaseParser):
    # .EU whois server disclaimer:
    # % The EURid WHOIS service on port 43 (textual whois) never
    # % discloses any information concerning the registrant.

    _eu_expressions = {
        BaseKeys.REGISTRAR: r"Registrar:\n.*Name: (.+)",
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._eu_expressions)

    def parse(self, blob: str) -> Dict[str, Any]:
        parsed_output = super().parse(blob)
        # find name servers
        parsed_output[BaseKeys.NAME_SERVERS] = self.find_multiline_match("Name servers:", blob)
        return parsed_output


class RegexDE(BaseParser):
    # .de disclaimer (very hard to extract information from this provider):
    #
    # % The DENIC whois service on port 43 doesn't disclose any information concerning
    # % the domain holder, general request and abuse contact.
    # % This information can be obtained through use of our web-based whois service
    # % available at the DENIC website:
    # % http://www.denic.de/en/domains/whois-service/web-whois.html

    _de_expressions = {
        BaseKeys.UPDATED: r'Changed: *(.+)',
        BaseKeys.NAME_SERVERS: r'Nserver: *(.+)',
        BaseKeys.DOMAIN_NAME: r'Domain: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._de_expressions)


class RegexUK(BaseParser):
    _uk_expressions = {
        BaseKeys.CREATED: r'Registered on:\s*(\d{2}-\w{3}-\d{4})',
        BaseKeys.UPDATED: r'Last updated:\s*(\d{2}-\w{3}-\d{4})',
        BaseKeys.EXPIRES: r'Expiry date:\s*(\d{2}-\w{3}-\d{4})',
        BaseKeys.REGISTRAR: r'Registrar:\s*(.+)',
        BaseKeys.REGISTRANT_NAME: r'Registrant:\n *(.+)',
        BaseKeys.STATUS: r'Registration status:\n *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._uk_expressions)

    def parse(self, blob: str) -> Dict[str, Any]:
        parsed_output = super().parse(blob)
        # handle registrant address
        address_match = re.search(r"Registrant's address: *(.+)Data valid", blob, re.DOTALL)
        if address_match:
            address_pieces = [m.strip() for m in address_match.group(1).split('\n') if m.strip()]
            parsed_output[BaseKeys.REGISTRANT_ADDRESS] = ", ".join(address_pieces)
        # find name servers
        parsed_output[BaseKeys.NAME_SERVERS] = self.find_multiline_match("Name servers:", blob)
        return parsed_output


class RegexJP(BaseParser):
    _jp_expressions = {
        BaseKeys.REGISTRANT_NAME: r'\[Registrant\] *(.+)',
        BaseKeys.CREATED: r'\[登録年月日\] *(.+)',
        BaseKeys.EXPIRES: r'\[(?:有効限|有効期限)\]*(.+)',
        BaseKeys.STATUS: r'\[状態\] *(.+)',
        BaseKeys.UPDATED: r'\[最終更新\] *(.+)',
        BaseKeys.NAME_SERVERS: r'\[Name Server\] *(.+)'
    }

    def __init__(self):
        super().__init__()

        self.update_reg_expressions(self._jp_expressions)

    def parse(self, blob: str) -> Dict[str, Any]:
        parsed_output = super().parse(blob)
        address_match = re.search(r"\[Postal Address\]([^\[|.]+)\[\w+\](.+)", blob, re.DOTALL)
        if address_match:
            address_pieces = [m.strip() for m in address_match.group(1).split('\n') if m.strip()]
            parsed_output[BaseKeys.REGISTRANT_ADDRESS] = ", ".join(address_pieces)
        return parsed_output


class RegexAU(BaseParser):
    _au_expressions = {
        BaseKeys.UPDATED: r'Last Modified: (\d{2}-\w{3}-\d{4})',
        BaseKeys.REGISTRAR: r'Registrar Name:\s *(.+)',
        BaseKeys.REGISTRANT_NAME: r'Registrant: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._au_expressions)


class RegexAT(BaseParser):
    _at_expressions = {
        BaseKeys.DOMAIN_NAME: r'domain: *(.+)',
        BaseKeys.REGISTRAR: r'registrar: *(.+)',
        BaseKeys.REGISTRANT_NAME: r'personname: *(.+)',
        BaseKeys.REGISTRANT_ADDRESS: r'street address: *(.+)',
        BaseKeys.REGISTRANT_ZIPCODE: r'postal code: *(.+)',
        BaseKeys.REGISTRANT_CITY: r'city: *(.+)',
        BaseKeys.REGISTRANT_COUNTRY: r'country: *(.+)',
        BaseKeys.UPDATED: r'changed: *(.+)',
        BaseKeys.NAME_SERVERS: r'nserver :*(.+)'
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._at_expressions)


class RegexBE(BaseParser):
    _be_expressions = {
        BaseKeys.DOMAIN_NAME: r'Domain: *(.+)',
        BaseKeys.CREATED: r'Registered: *(.+)',
        BaseKeys.REGISTRAR: r'Registrar:\n.+Name: *(.+)',
        BaseKeys.REGISTRANT_NAME: r'Registrant:\n *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._be_expressions)

    def parse(self, blob: str) -> Dict[str, Any]:
        parsed_output = super().parse(blob)
        parsed_output[BaseKeys.NAME_SERVERS] = self.find_multiline_match("Name servers:", blob)
        return parsed_output


class RegexRF(BaseParser):  # same as RU

    def __init__(self):
        super().__init__()

        self.update_reg_expressions(RegexRU._ru_expressions)


class RegexSU(BaseParser):  # same as RU

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(RegexRU._ru_expressions)


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
        self.update_reg_expressions(self._kg_expressions)

    def parse(self, blob: str) -> Dict[str, Any]:
        parsed_output = super().parse(blob)
        parsed_output[BaseKeys.NAME_SERVERS] = self.find_multiline_match("Name servers in the listed order:", blob)
        return parsed_output


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
        self.update_reg_expressions(self._ch_expressions)


class RegexLI(BaseParser):  # same as CH

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(RegexCH._ch_expressions)


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
        BaseKeys.NAME_SERVERS: r'nserver: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._se_expressions)


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
        self.update_reg_expressions(self._tr_expressions)


class RegexIS(BaseParser):
    _is_expressions = {
        BaseKeys.DOMAIN_NAME: r'domain: *(.+)',
        BaseKeys.CREATED: r'created\.*: *(.+)',
        BaseKeys.EXPIRES: r'expires\.*: *(.+)',
        BaseKeys.DNSSEC: r'dnssec\.*: *(.+)',
        BaseKeys.NAME_SERVERS: r'nserver\.*: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._is_expressions)

    def parse(self, blob: str) -> Dict[str, Any]:
        parsed_output = super().parse(blob)
        # find first instance of person/role (registrant)
        registrant_block = False
        registrant_name = None
        addresses = []
        for line in blob.split('\n'):
            if line.startswith('role') or line.startswith('person'):
                if registrant_block:
                    break
                else:
                    registrant_name = line.split(':')[-1].strip()
                    registrant_block = True
            elif line.startswith('address:'):
                address = line.split(':')[-1].strip()
                addresses.append(address)

        parsed_output[BaseKeys.REGISTRANT_NAME] = registrant_name
        # join the address lines together and save
        parsed_output[BaseKeys.REGISTRANT_ADDRESS] = ", ".join(addresses)
        return parsed_output


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
        self.update_reg_expressions(self._dk_expressions)


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
        self.update_reg_expressions(self._pt_expression)


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

        self.update_reg_expressions(self._lu_expressions)


class RegexCZ(BaseParser):
    _cz_expressions = {
        BaseKeys.DOMAIN_NAME: r'domain: *(.+)',
        BaseKeys.REGISTRANT_NAME: r'name: *(.+)',
        BaseKeys.REGISTRANT_ORGANIZATION: r'org: *(.+)',
        BaseKeys.REGISTRAR: r'registrar: *(.+)',
        BaseKeys.CREATED: r'registered: *(.+)',
        BaseKeys.UPDATED: r'changed: *(.+)',
        BaseKeys.EXPIRES: r'expire: *(.+)',
        BaseKeys.NAME_SERVERS: r'nserver: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._cz_expressions)

    def parse(self, blob: str) -> Dict[str, Any]:
        parsed_output = super().parse(blob)
        addresses = []
        seen_contact = False
        # extract address from registrant info block
        for line in blob.split('\n'):
            # check that this is first "contact" block
            if line.startswith('contact:'):
                if not seen_contact:
                    seen_contact = True
                else:
                    # if not; stop
                    break
            # append address
            elif line.startswith('address:'):
                line = line.split(':')[-1].strip()
                addresses.append(line)
        # just combine address lines; don't assume city/zipcode/country happen in any specific order
        address = ", ".join(addresses)
        parsed_output[BaseKeys.REGISTRANT_ADDRESS] = address
        return parsed_output


class RegexHR(BaseParser):
    _hr_expressions = {
        BaseKeys.DOMAIN_NAME: r'Domain Name: *(.+)',
        BaseKeys.UPDATED: r'Updated Date: *(.+)',
        BaseKeys.CREATED: r'Creation Date: *(.+)',
        BaseKeys.EXPIRES: r'Registrar Registration Expiration Date: *(.+)',
        BaseKeys.NAME_SERVERS: r'Name Server: *(.+)',
        BaseKeys.REGISTRANT_NAME: r'Registrant Name:\s(.+)',
        BaseKeys.REGISTRANT_ADDRESS: r'Registrant Street:\s*(.+)',
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._hr_expressions)


class RegexHK(BaseParser):
    _hk_expressions = {
        BaseKeys.STATUS: r'Domain Status: *(.+)',
        BaseKeys.DNSSEC: r'DNSSEC: *(.+)',
        BaseKeys.REGISTRAR: r'Registrar Name: *(.+)',
        BaseKeys.REGISTRANT_NAME: r'Registrant Contact Information:\s*Company English Name.*:(.+)',
        BaseKeys.REGISTRANT_ADDRESS: r'(?<=Registrant Contact Information:)[\s\S]*?Address: (.*)',
        BaseKeys.REGISTRANT_COUNTRY: r'[Registrant Contact Information\w\W]+Country: ([\S\ ]+)',
        # 'registrant_email': r'[Registrant Contact Information\w\W]+Email: ([\S\ ]+)',
        BaseKeys.UPDATED: r'Updated Date: *(.+)',
        BaseKeys.CREATED: r'[Registrant Contact Information\w\W]+Domain Name Commencement Date: (.+)',
        BaseKeys.EXPIRES: r'[Registrant Contact Information\w\W]+Expiry Date: (.+)',
        BaseKeys.NAME_SERVERS: r'Name Servers Information:\s+((?:.+\n)*)'
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._hk_expressions)


class RegexUA(BaseParser):
    _ua_expressions = {
        BaseKeys.DOMAIN_NAME: r'domain: *(.+)',
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
        self.update_reg_expressions(self._ua_expressions)


class RegexCN(BaseParser):
    _cn_expressions = {
        BaseKeys.REGISTRAR: r'Sponsoring Registrar: *(.+)',
        BaseKeys.CREATED: r'Registration Time: *(.+)',
        BaseKeys.EXPIRES: r'Expiration Time: *(.+)',
        BaseKeys.REGISTRANT_NAME: r'Registrant: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._cn_expressions)


class RegexAR(BaseParser):
    _ar_expressions = {
        BaseKeys.DOMAIN_NAME: r'domain: *(.+)',
        BaseKeys.REGISTRAR: r'registrar: *(.+)',
        BaseKeys.UPDATED: r'changed: *(.+)',
        BaseKeys.CREATED: r'created: *(.+)',
        BaseKeys.EXPIRES: r'expire: *(.+)',
        BaseKeys.NAME_SERVERS: r'nserver: *(.+) \(.*\)',
        BaseKeys.REGISTRANT_NAME: r'name: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._ar_expressions)


class RegexBY(BaseParser):
    _by_expressions = {
        BaseKeys.DOMAIN_NAME: r'Domain Name: *(.+)',
        BaseKeys.REGISTRAR: r'Registrar: *(.+)',
        BaseKeys.REGISTRANT_NAME: r'Person: *(.+)',
        BaseKeys.REGISTRANT_ORGANIZATION: r'Org: *(.+)',
        BaseKeys.REGISTRANT_COUNTRY: r'Country: *(.+)',
        BaseKeys.REGISTRANT_ADDRESS: r'Address: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._by_expressions)


class RegexCR(BaseParser):
    _cr_expressions = {
        BaseKeys.DOMAIN_NAME: r'domain: *(.+)',
        BaseKeys.REGISTRANT_NAME: r'name: *(.+)',
        BaseKeys.REGISTRAR: r'registrar: *(.+)',
        BaseKeys.UPDATED: r'changed: *(.+)',
        BaseKeys.CREATED: r'registered: *(.+)',
        BaseKeys.EXPIRES: r'expire: *(.+)',
        BaseKeys.NAME_SERVERS: r'nserver: *(.+)',
        BaseKeys.REGISTRANT_ORGANIZATION: r'org: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._cr_expressions)

    def parse(self, blob: str) -> Dict[str, Any]:
        # CR server has the same format as CZ
        return RegexCZ().parse(blob)


class RegexVE(BaseParser):  # double check
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
        self.update_reg_expressions(self._ve_expressions)


class RegexAE(BaseParser):
    _ae_expressions = {
        BaseKeys.STATUS: r'Status: *(.+)',
        BaseKeys.REGISTRANT_NAME: r'Registrant Contact Name: *(.+)',
        BaseKeys.REGISTRANT_ORGANIZATION: r'Registrant Contact Organisation: *(.+)',
        BaseKeys.REGISTRAR: r'Registrar Name: *(.+)'
    }

    def __init__(self):
        super().__init__()
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
        BaseKeys.CREATED: r'Created:\s*(.+)',
        BaseKeys.UPDATED: r'Last updated:\s*(.+)',
        BaseKeys.NAME_SERVERS: r'Name Server Handle\.*: *(.+)',
        BaseKeys.REGISTRAR: r'Registrar Handle\.*: *(.+)',
        BaseKeys.DOMAIN_NAME: r'Domain Name\.*: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._no_expressions)


class RegexKZ(BaseParser):
    _kz_expressions = {
        BaseKeys.REGISTRAR: r'Current Registar:\s*(.+)',  # "Registar" typo exists on the whois server
        BaseKeys.CREATED: r'Domain created:\s*(.+)\s\(',
        BaseKeys.UPDATED: r'Last modified\s:\s*(.+)\s\(',
        BaseKeys.NAME_SERVERS: r'.+\sserver\.*:\s*(.+)',
        BaseKeys.STATUS: r'Domain status\s:\s(.+)',
        BaseKeys.REGISTRANT_ORGANIZATION: r'Organization Using Domain Name\nName\.*:\s(.+)',
        BaseKeys.REGISTRANT_ADDRESS: r'Street Address\.*:\s*(.+)',
        BaseKeys.REGISTRANT_CITY: r'City\.*:\s*(.+)',
        BaseKeys.REGISTRANT_ZIPCODE: r'Postal Code\.*:\s*(.+)',
        BaseKeys.REGISTRANT_COUNTRY: r'Country\.*:\s*(.+)',
        BaseKeys.REGISTRANT_NAME: r'Organization Name\.*:\s*(.+)'
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._kz_expressions)


class RegexIR(BaseParser):
    _ir_expressions = {
        BaseKeys.UPDATED: r'last-updated: *(.+)',
        BaseKeys.EXPIRES: r'expire-date: *(.+)',
        BaseKeys.REGISTRANT_ORGANIZATION: r'org: *(.+)',
        BaseKeys.REGISTRANT_NAME: r'remarks:\s+\(Domain Holder\) *(.+)',
        BaseKeys.REGISTRANT_ADDRESS: r'remarks:\s+\(Domain Holder Address\) *(.+)',
        BaseKeys.NAME_SERVERS: r'nserver: *(.+)',
        BaseKeys.DOMAIN_NAME: r'domain: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._ir_expressions)


class RegexTK(BaseParser):
    _tk_expressions = {
        BaseKeys.REGISTRANT_ORGANIZATION: r'(?<=Owner contact)[\s\S]*?Organization:(.*)',
        BaseKeys.REGISTRANT_NAME: r'(?<=Owner contact)[\s\S]*?Name:(.*)',
        BaseKeys.REGISTRANT_ADDRESS: r'(?<=Owner contact)[\s\S]*?Address:(.*)',
        BaseKeys.REGISTRANT_STATE: r'(?<=Owner contact)[\s\S]*?State:(.*)',
        BaseKeys.REGISTRANT_CITY: r'(?<=Owner contact)[\s\S]*?City:(.*)',
        BaseKeys.REGISTRANT_COUNTRY: r'(?<=Owner contact)[\s\S]*?Country:(.*)',
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._tk_expressions)

    def parse(self, blob: str) -> Dict[str, Any]:
        parsed_output = super().parse(blob)
        # handle multiline nameservers
        parsed_output[BaseKeys.NAME_SERVERS] = self.find_multiline_match('Domain nameservers:', blob)
        # a date parser exists for '%d/%m/%Y', but this interferes with the parser needed
        # for this one, which is '%m/%d/%Y', so this date format needs to be parsed separately here
        created_match = re.search(r'Domain registered: *(.+)', blob, re.IGNORECASE)
        if created_match:
            parsed_output[BaseKeys.CREATED] = datetime.datetime.strptime(created_match.group(1), '%m/%d/%Y')
        expires_match = re.search(r'Record will expire on: *(.+)', blob, re.IGNORECASE)
        if expires_match:
            parsed_output[BaseKeys.EXPIRES] = datetime.datetime.strptime(expires_match.group(1), '%m/%d/%Y')
        # split domain and status
        domain_name_match = re.search(f'Domain name:(?:.*?)*(.+)Owner contact:', blob, re.IGNORECASE | re.DOTALL)
        if domain_name_match:
            domain_and_status = domain_name_match.group(1).split(' is ')
            if len(domain_and_status) > 1:
                parsed_output[BaseKeys.DOMAIN_NAME] = self._process(domain_and_status[0])
                parsed_output[BaseKeys.STATUS] = [self._process(domain_and_status[1])]
            else:
                parsed_output[BaseKeys.DOMAIN_NAME] = domain_and_status
        return parsed_output


class RegexCC(BaseParser):
    _cc_expressions = {
        BaseKeys.STATUS: r'Domain Status: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._cc_expressions)


class RegexEDU(BaseParser):
    _edu_expressions = {
        BaseKeys.CREATED: 'Domain record activated: *(.+)',
        BaseKeys.UPDATED: 'Domain record last updated: *(.+)',
        BaseKeys.EXPIRES: 'Domain expires: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._edu_expressions)

    def parse(self, blob: str) -> Dict[str, Any]:
        parsed_output = super().parse(blob)
        registrant_match = re.search(r'Registrant:*(.+)Administrative Contact', blob, re.DOTALL | re.IGNORECASE)
        if registrant_match:
            reg_info_raw = registrant_match.group(1).split('\n')
            # remove duplicates and empty strings
            reg_info_clean = []
            for value in reg_info_raw:
                value = value.strip()
                if value and value not in reg_info_clean:
                    reg_info_clean.append(value)
            # country is usually either last or third to last
            country_index = -3
            for i, value in enumerate(reg_info_clean):
                if len(value) == 2:
                    country_index = i
                    break

            org = reg_info_clean[0]
            address = ", ".join(reg_info_clean[1:country_index])
            country = reg_info_clean[country_index]

            parsed_output[BaseKeys.REGISTRANT_NAME] = org
            parsed_output[BaseKeys.REGISTRANT_ORGANIZATION] = org
            parsed_output[BaseKeys.REGISTRANT_COUNTRY] = country
            parsed_output[BaseKeys.REGISTRANT_ADDRESS] = address

        # handle multiline nameservers
        parsed_output[BaseKeys.NAME_SERVERS] = self.find_multiline_match('Name Servers:', blob)
        return parsed_output


class RegexLV(BaseParser):
    _lv_expressions = {
        BaseKeys.REGISTRAR: r'\[Registrar\]\n(?:.*)\nName:(.*)+',
        BaseKeys.REGISTRANT_NAME: r'\[Holder\]\n(?:.*)\nName:(.*)+',
        BaseKeys.REGISTRANT_ADDRESS: r'\[Holder\]\n(?:.*)\Address:(.*)+',
        BaseKeys.NAME_SERVERS: r'Nserver: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._lv_expressions)


class RegexGQ(BaseParser):
    _gq_expressions = {}

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._gq_expressions)

    def parse(self, blob: str) -> Dict[str, Any]:
        # GQ server has the same format as TK
        return RegexTK().parse(blob)


class RegexNL(BaseParser):
    _nl_expressions = {
        BaseKeys.REGISTRAR: r'Registrar:\n(.+)'
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._nl_expressions)

    def parse(self, blob: str) -> Dict[str, Any]:
        parsed_output = super().parse(blob)
        # handle multiline nameservers
        parsed_output[BaseKeys.NAME_SERVERS] = self.find_multiline_match('Domain nameservers:', blob)
        return parsed_output


class RegexMA(BaseParser):
    _ma_expressions = {
        BaseKeys.REGISTRAR: r'Sponsoring Registrar: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._ma_expressions)


class RegexGE(BaseParser):
    _ge_expressions = {
        BaseKeys.REGISTRANT_NAME: r'Registrant: *(.+)',
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._ge_expressions)


class RegexGG(BaseParser):
    _gg_expressions = {
        BaseKeys.DOMAIN_NAME: r'Domain:\n*(.+)',
        BaseKeys.REGISTRANT_NAME: r'Registrant:\n*(.+)',
        BaseKeys.REGISTRAR: r'Registrar:\n*(.+)',
        BaseKeys.CREATED: r'Registered on *(.+) at',
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._gg_expressions)

    def parse(self, blob: str) -> Dict[str, Any]:
        parsed_output = super().parse(blob)
        # parse created date
        created_match = parsed_output.get('created')  # looks like 30th April 2003; need to remove day suffix
        if created_match and isinstance(created_match, str):
            date_string = re.sub(r'(\d)(st|nd|rd|th)', r'\1', created_match)
            parsed_output[BaseKeys.CREATED] = datetime.datetime.strptime(date_string, '%d %B %Y')
        # handle multiline nameservers and statuses
        parsed_output[BaseKeys.NAME_SERVERS] = self.find_multiline_match('Name servers:', blob)
        parsed_output[BaseKeys.STATUS] = self.find_multiline_match('Domain status:', blob)
        return parsed_output


class RegexAW(BaseParser):
    _aw_expressions = {
        BaseKeys.REGISTRAR: r'Registrar:\n*(.+)',
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._aw_expressions)

    def parse(self, blob: str) -> Dict[str, Any]:
        parsed_output = super().parse(blob)
        parsed_output[BaseKeys.NAME_SERVERS] = self.find_multiline_match('Domain nameservers:', blob)
        return parsed_output


class RegexAX(BaseParser):
    _ax_expressions = {
        BaseKeys.DOMAIN_NAME: r'domain\.+: *(.+)',
        BaseKeys.REGISTRAR: r'registrar\.+: *(.+)',
        BaseKeys.REGISTRANT_NAME: r'name\.+: *(.+)',
        BaseKeys.REGISTRANT_COUNTRY: r'country\.+: *(.+)',
        BaseKeys.CREATED: r'created\.+: *(.+)',
        BaseKeys.EXPIRES: r'expires\.+: *(.+)',
        BaseKeys.UPDATED: r'modified\.+: *(.+)',
        BaseKeys.STATUS: r'status\.+: *(.+)',
        BaseKeys.NAME_SERVERS: r'nserver\.+: *(.+)'
    }

    def __init__(self):
        super().__init__()
        self.update_reg_expressions(self._ax_expressions)

    def parse(self, blob: str) -> Dict[str, Any]:
        parsed_output = super().parse(blob)
        addresses = self.find_match(r'address\.+: *(.+)', blob, many=True)
        if addresses:
            parsed_output[BaseKeys.REGISTRANT_ADDRESS] = ', '.join(addresses)
        return parsed_output
